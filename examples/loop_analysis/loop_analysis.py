import sys
import os
import logging
import networkx as nx

import angr

logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

class LoopAnalysis(Analysis):

    def __init__(self, cached_results_path=None):
        super().__init__(cached_results_path)

    def results_constructor(self):
        return LoopResults

    def analyze(self, analysis_target, analysis_results):
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)

            callgraph = proj.kb.callgraph

            for cg_scc_addrs in self.nontrivial_sccs(callgraph):
                func_graph_sccs = []

                detected_loop = self.create_detected_loop(cfg, cg_scc_addrs)

                for cg_scc_addr in cg_scc_addrs:
                    caller_func = cfg.functions.function(cg_scc_addr)
                    if caller_func is None:
                        # Why would angr do this?
                        continue
                    caller_func_sccs = list(self.nontrivial_sccs(caller_func.graph))
                    #print('caller func: {} call_sites: {} sccs: {}'.format(caller_func.name, list(caller_func.get_call_sites()), list(caller_func_sccs)))

                    for call_site in caller_func.get_call_sites():
                        #print('call site: {}'.format(call_site))

                        for func_scc in caller_func_sccs:
                            #print('scc: {}'.format(func_scc))
                            # If the call site is in an SCC of the caller function, it means the function is called in a loop
                            call_site_node = cfg.model.get_any_node(call_site)
                            call_site_block_node = angr.codenode.BlockNode(call_site, call_site_node.size)
                            #print(call_site_block_node, func_scc)
                            if call_site_block_node in func_scc:
                                call_target = caller_func.get_call_target(call_site)

                                called_func = cfg.functions.function(call_target)
                                if called_func is None:
                                    continue

                                # If the function called in a loop is also in the callgraph loop, we log it.
                                if called_func.addr in cg_scc_addrs:
                                    fgle = FuncGraphLoopEntry(caller_func.name, caller_func.addr, called_func.name, called_func.addr, [block_node.addr for block_node in func_scc])
                                    detected_loop.add_func_graph_loop_entry(fgle)
                analysis_results.add_detected_loop(detected_loop)                                  


        except Exception as e:
            #raise e
            analysis_results.add_err(str(e))

    def create_detected_loop(self, cfg, call_graph_scc_addrs):
        call_graph_loop = []
        for cg_scc_addr in call_graph_scc_addrs:
            caller_func = cfg.functions.function(cg_scc_addr)
            if caller_func is None:
                caller_func_name, caller_func_addr = '?', cg_scc_addr
            else:
                caller_func_name, caller_func_addr = caller_func.name, caller_func.addr
            call_graph_loop.append(CallGraphLoopEntry(caller_func_name, caller_func_addr))
        detected_loop  = DetectedLoop(call_graph_loop)
        return detected_loop

    def nontrivial_sccs(self, graph):
        return filter(lambda scc_nodes: len(graph.subgraph(scc_nodes).edges()) > 0, nx.strongly_connected_components(graph))


class LoopResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.detected_loops = []
        self.errs = []


    def add_detected_loop(self, detected_loop):
        self.detected_loops.append(detected_loop)

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['errs'] = len(self.errs)
        tracked_events['loops'] = len(self.detected_loops)

        return tracked_events

    def add_err(self, err):
        self.errs.append(err)

    def copy_from_inner(self, other_analysis_results):

        for detected_loop in other_analysis_results.detected_loops:
            self.add_detected_loop(detected_loop)
        for err in other_analysis_results.errs:
            self.add_err(err)

class DetectedLoop:

    def __init__(self, call_graph_loop):
        self.call_graph_loop = call_graph_loop
        self.function_graph_loops = []

    def add_func_graph_loop_entry(self, func_graph_loop):
        self.function_graph_loops.append(func_graph_loop)

class CallGraphLoopEntry:

    def __init__(self, func_name: str, func_addr: int):
        self.func_name = func_name
        self.func_addr = func_addr

class FuncGraphLoopEntry:

    def __init__(self, caller_func_name, caller_func_addr, called_func_name, called_func_addr, func_loop_addrs):
        self.caller_func_name = caller_func_name
        self.caller_func_addr = caller_func_addr
        self.called_func_name = called_func_name
        self.called_func_addr = called_func_addr
        self.func_loop_addrs = func_loop_addrs
