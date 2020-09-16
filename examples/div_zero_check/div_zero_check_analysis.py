import sys
import os
import logging
import networkx as nx

import angr
import pyvex

logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

class DivZeroAnalysis(Analysis):

    def results_constructor(self):
        return DivZeroAnalysisResults

    def analyze(self, analysis_target, analysis_results):
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            self._cfg = proj.analyses.CFGFast()
            div_stmts = self.get_div_stmts()
            analysis_results.set_div_stmts(div_stmts)
            for i, div_stmt in enumerate(div_stmts):
                target_block_addr = div_stmt.block_addr
                target_stmt_idx = div_stmt.stmt_idx
                target_node = self._cfg.model.get_any_node(addr=target_block_addr)
                for path in self.get_execution_paths(self._cfg, target_node):
                    path_node_set = set(node for node in path)
                    start_node = path[0]
                    end_node = path[-1]
                    assert end_node.addr == target_node.addr, "The execution path does not end with the block of the div statement"
                    start_state = proj.factory.blank_state(addr=start_node.addr)
                    def avoid_func(state):
                        state_node = self._cfg.model.get_any_node(addr=state.addr, anyaddr=True)
                        if state_node in path_node_set:
                            return False
                        return True
                    def break_statement(state):
                        try:
                            state_stmt_idx = state.inspect.statement
                            state_node = self._cfg.model.get_any_node(addr=state.addr, anyaddr=True)
                            state_block = state_node.block
                            state_irsb = state_block.vex
                            if state_block.addr != target_block_addr or state_stmt_idx != target_stmt_idx:
                                return
                            # This matches the target statement, so we can assume it is a Div statement
                            if state_stmt_idx > len(state_irsb.statements):
                                analysis_results.add_err("error in break_statement: state_block_addr: {} state_stmt_idx: {} num statements: {}".format(state_block.addr, state_stmt_idx, len(state_irsb.statements)))
                                return

                            div_vex_stmt = state_irsb.statements[state_stmt_idx]
                            tmp_operands = []
                            div_vex_stmt_exprs = list(div_vex_stmt.expressions)
                            if len(div_vex_stmt_exprs) != 3:
                                analysis_results.add_error("Unexpected number of expressions in div stmt: {} (addr: 0x{:x} stmt_idx: {})".format(div_vex_stmt, target_block_addr, target_stmt_idx))
                                return
                            divisor_expr  = div_vex_stmt_exprs[2]
                            if type(divisor_expr) == pyvex.expr.RdTmp:
                                tmp_divisor = divisor_expr.tmp
                                tmp_divisor_expr = state.scratch.tmp_expr(tmp_divisor)

                                print(tmp_divisor_expr)
                                zero_check = state.solver.satisfiable(extra_constraints=[tmp_divisor_expr == 0])
                                analysis_results.add_div_stmt_check((start_node.addr, div_stmt, str(div_vex_stmt), tmp_divisor, zero_check))
                        except Exception as e:
                            analysis_results.add_err("error in break_statement: {}".format(str(e)))



                    start_state.inspect.b('statement', when=angr.BP_BEFORE, action=break_statement)
                    simgr = proj.factory.simulation_manager(start_state)
                    simgr.explore(find=end_node.addr, avoid=avoid_func)
                    # Now the end state is in the 'found' stash
                    simgr.step(stash='found')
                #if i > 100:
                #    break


        except Exception as e:
            analysis_results.add_err(str(e))

        #return analysis_results

    def get_execution_paths(self, cfg, node):
        func_addr = node.function_address
        if func_addr == node.addr:
            return [[node]]
        func_entry_node = cfg.model.get_any_node(addr=func_addr)


        paths = []
        for path in nx.all_simple_paths(cfg.graph, func_entry_node, node):
            paths.append(path)
        return paths


    def get_div_stmts(self):
        div_stmts = []
        for node in self._cfg.model.nodes():
            block = node.block
            if block is None:
                continue
            irsb = block.vex
            for stmt_idx, stmt in enumerate(irsb.statements):
                for expr in stmt.expressions:
                    if type(expr) == pyvex.expr.Binop and 'Div' in expr.op:
                        div_stmts.append(DivStmt(node.addr, stmt_idx))
                        break
        return div_stmts


class DivStmt:
    def __init__(self, block_addr, stmt_idx):
        self.block_addr = block_addr
        self.stmt_idx = stmt_idx

class DivZeroAnalysisResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.div_stmts = []
        self.div_stmt_checks = []
        self.errs = []


    def set_div_stmts(self, div_stmts):
        self.div_stmts = div_stmts[::]

    def add_div_stmt_check(self, check):
        self.div_stmt_checks.append(check)

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['errs'] = len(self.errs)

        return tracked_events

    def add_err(self, err):
        self.errs.append(err)

    def copy_from_inner(self, other_analysis_results):

        self.set_div_stmts(other_analysis_results.div_stmts)
        for div_stmt_check in other_analysis_results.div_stmt_checks:
            self.add_div_stmt_check(div_stmt_check)
        for err in self.errs:
            self.add_err(err)

