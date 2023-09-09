import sys
import os
import logging
import re


logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('pyvex').disabled = True
logging.getLogger('pyvex').propagate = False
logging.getLogger('claripy').disabled = True
logging.getLogger('claripy').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

import angr
import pyvex

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

class MathDetectionAnalysis(Analysis):

    def results_constructor(self):
        return MathDetectionAnalysisResults

    def analyze(self, analysis_target, analysis_results):
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            self._cfg = proj.analyses.CFGFast(normalize=True)
            for func_addr, func in self._cfg.functions.items():
                if func.alignment or func.is_plt or func.is_simprocedure:
                    continue
                func_name = func.name
                used_fp_offset_tally, stmts_with_binop_fp_math_exprs, math_fp_stmt_density, math_int_stmt_density = get_fp_features(proj, func)
                feats = FpFeatures(used_fp_offset_tally, stmts_with_binop_fp_math_exprs, math_fp_stmt_density, math_int_stmt_density)
                analysis_results.add_features(func_name, func_addr, feats)

        except Exception as e:
            analysis_results.add_err(str(e))


def get_fp_features(proj, func):
    used_fp_offset_tally = {}
    stmts_with_binop_fp_math_exprs = set()
    stmts_with_binop_int_math_exprs = set()
    func_num_stmts = count_func_num_stmts(proj, func)
    for block in func.blocks:
        if block.size == 0:
            #print("0 size block: 0x{:x}".format(block.addr))
            continue
        unop_block = proj.factory.block(addr=block.addr, opt_level=-1, size=block.size)
        irsb = unop_block.vex
        stmts_by_insn = split_block_into_insn_stmts(unop_block)
        for stmt in irsb.statements:
            if stmt.tag == 'Ist_IMark':
                #print("Insn: 0x{:x}".format(stmt.addr))
                continue
            curr_used_fp_offset_tally = get_used_fp_offset_tallies(proj, irsb, stmt)
            for offset, tally in curr_used_fp_offset_tally.items():
                if offset not in used_fp_offset_tally:
                    used_fp_offset_tally[offset] = tally
                else:
                    used_fp_offset_tally[offset] += tally

            for expr in stmt.expressions:
                if expr.tag == 'Iex_Binop':
                    if is_fp_type(proj, irsb, expr) and is_math_op(expr.op):
                        stmts_with_binop_fp_math_exprs.add(stmt)
                        break
                    elif is_int_type(proj, irsb, expr) and is_math_op(expr.op):
                        stmts_with_binop_int_math_exprs.add(stmt)
                        break


    if func_num_stmts == 0:
        math_fp_stmt_density = 0
        math_int_stmt_density = 0
    else:
        math_fp_stmt_density = len(stmts_with_binop_fp_math_exprs) / func_num_stmts
        math_int_stmt_density = len(stmts_with_binop_int_math_exprs) / func_num_stmts

    return used_fp_offset_tally, stmts_with_binop_fp_math_exprs, math_fp_stmt_density, math_int_stmt_density

def is_math_op(op):
    op = op.lower()
    if any(['add' in op, 'sub' in op, 'mul' in op, 'div' in op]):
        return True
    if any(['sin' in op, 'cos' in op, 'tan' in op]):
        return True

    return False

def count_func_num_stmts(proj, func):
    num_stmts = 0
    for block in func.blocks:
        if block.size == 0:
            continue
        unop_block = proj.factory.block(addr=block.addr, opt_level=-1, size=block.size)
        irsb = unop_block.vex
        num_stmts += len(irsb.statements)

    return num_stmts

def is_fp_stmt(proj, irsb, stmt):
    if is_fp_type(proj, irsb, stmt):
        return True

    for expr in stmt.expressions:
        if is_fp_type(proj, irsb, expr):
            return True

    return False

def is_fp_type(proj, irsb, stmt_or_expr):
    type_match_s = parse_type(proj, irsb, stmt_or_expr)
    if type_match_s == 'D' or type_match_s == 'V' or type_match_s == 'V' or type_match_s == 'F':
        return True
    return False

def is_int_type(proj, irsb, stmt_or_expr):
    type_match_s = parse_type(proj, irsb, stmt_or_expr)
    if type_match_s == 'I':
        return True

    return False

def parse_type(proj, irsb, stmt_or_expr):
    typ = stmt_or_expr.typecheck(irsb.tyenv)
    if isinstance(typ, bool):
        return False
    type_match = re.match(r'Ity_(?P<type>I|D|V|F)\d+', typ)
    if not type_match:
        raise Exception("Could not interpret type {} in: {}".format(typ, stmt_or_expr))

    type_match_s = type_match.group('type')
    return type_match_s

def get_used_fp_offset_tallies(proj, irsb, stmt):
    used_fp_offset_tally = {}
    if stmt.tag == 'Ist_Put':
        offset = stmt.offset
        #print(stmt)
        if is_fp_reg(proj, offset):
            if offset not in used_fp_offset_tally:
                used_fp_offset_tally[offset] = 0
            used_fp_offset_tally[offset] += 1
    for expr in stmt.expressions:
        if expr.tag == 'Iex_Get':
            offset = expr.offset
            #print(expr)
            if is_fp_reg(proj, offset):
                if offset not in used_fp_offset_tally:
                    used_fp_offset_tally[offset] = 0
                used_fp_offset_tally[offset] += 1
    return used_fp_offset_tally

def is_fp_reg(proj, offset):
    #reg_name = proj.arch.translate_register_name(offset)
    #if reg_name is None:
    #print("offset: {} reg_name: {}".format(offset, reg_name))
    #reg = proj.arch.get_register_by_name(reg_name)
    base = proj.arch.get_base_register(offset)
    if base is None:
        print("WARN: Could not get base register of offset: {}".format(offset))
        return False
    base_offset, base_size = base
    base_reg_name = proj.arch.translate_register_name(base_offset)
    base_reg = proj.arch.get_register_by_name(base_reg_name)

    is_fp = base_reg.floating_point
    #print("{}: {}".format(base_reg_name, is_fp))
    if is_fp:
        return True

    if proj.arch.name == 'AMD64':
        return base_reg_name.startswith('xmm') or base_reg_name.startswith('ymm')

    if proj.arch.name == 'ARMCortexM':
        return base_reg_name.startswith('s') or base_reg_name.startswith('d')

    raise Exception("I don't know what the floating point registers are for arch: {}".format(proj.arch))


def split_block_into_insn_stmts(block):
    irsb = block.vex
    stmts = irsb.statements
    if len(stmts) == 0:
        return []
    assert stmts[0].tag == 'Ist_IMark', "Statements does not start with an IMark: {}".format(stmts[0])

    stmts_by_insn = []
    for stmt in stmts:
        if stmt.tag == 'Ist_IMark':
            insn_stmts = []
            stmts_by_insn.append(insn_stmts)
        insn_stmts.append(stmt)

    assert sum([len(l) for l in stmts_by_insn]) == len(stmts)
    return stmts_by_insn

class MathDetectionAnalysisResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.func_addr_to_features = {}
        self.errs = []


    def add_features(self, func_name, func_addr, fp_features):
        self.func_addr_to_features[(func_name, func_addr)] = fp_features

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['errs'] = len(self.errs)

        return tracked_events

    def add_err(self, err):
        self.errs.append(err)

    def copy_from_inner(self, other_analysis_results):

        for (func_name, func_addr), fp_features in other_analysis_results.func_addr_to_features.items():
            self.add_features(func_name, func_addr, fp_features)
        for err in other_analysis_results.errs:
            self.add_err(err)

class FpFeatures:

    def __init__(self, used_fp_offset_tally, stmts_with_binop_fp_math_exprs, math_fp_stmt_density, math_int_stmt_density):
        self.used_fp_offset_tally = used_fp_offset_tally
        self.stmts_with_binop_fp_math_exprs = stmts_with_binop_fp_math_exprs
        self.math_fp_stmt_density = math_fp_stmt_density
        self.math_int_stmt_density = math_int_stmt_density
