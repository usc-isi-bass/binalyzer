import angr
import sys
import os
import itertools
import networkx as nx
import logging

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False
logging.getLogger('claripy').disabled = True
logging.getLogger('claripy').propagate = False

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

class DataFlowAnalysis(Analysis):

    def results_constructor(self):
        return DataFlowAnalysisResults

    def analyze(self, analysis_target, analysis_results):
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            cfg_fast = proj.analyses.CFGFast()
            cfg = proj.analyses.CFGEmulated(context_sensitivity_level=1, keep_state=True, state_add_options=angr.sim_options.refs)

            main_func = cfg.functions.function(name='main')
            assert main_func is not None, "Could not find \"main\" function"
            main_func_addr = main_func.addr
            #ddg = proj.analyses.DDG(cfg, start=main_func_addr)
            ddg = proj.analyses.DDG(cfg)

            num_nodes = len(list(ddg.graph.nodes()))
            num_edges = len(list(ddg.graph.edges()))
            analysis_results.set_num_nodes(num_nodes)
            analysis_results.set_num_edges(num_edges)
            ddg_nodes = ddg.graph.nodes()
            insns_in_ddg = set()
            for code_location in ddg_nodes:
                insn_addr = code_location.ins_addr
                insns_in_ddg.add(insn_addr)

            insns_in_cfg = set()
            for node in cfg_fast.model.nodes():
                for insn_addr in node.instruction_addrs:
                    insns_in_cfg.add(insn_addr)

            insns_in_both = insns_in_ddg.intersection(insns_in_cfg)
            insns_in_ddg_not_cfg = insns_in_ddg - insns_in_cfg
            insns_in_cfg_not_ddg = insns_in_cfg - insns_in_ddg

            analysis_results.set_insns_in_ddg_not_cfg(insns_in_ddg_not_cfg)
            analysis_results.set_insns_in_cfg_not_ddg(insns_in_cfg_not_ddg)
            analysis_results.set_insns_in_both(insns_in_both)

            longest_path = []
            for cl1, cl2 in itertools.islice(filter(lambda pair: pair[0] != pair[1] and nx.has_path(ddg.graph, pair[0], pair[1]), itertools.product(ddg_nodes, ddg_nodes)), 0, 10000):
                #assert nx.has_path(ddg.graph, cl1, cl2)
                #if not nx.has_path(ddg.graph, cl1, cl2):
                #    continue

                #for local_path in itertools.islice(nx.all_simple_paths(ddg.graph, cl1, cl2), 0, 1):
                #    if len(local_path) > len(longest_path):
                #        longest_path = local_path
                local_longest_path = max(itertools.islice(nx.all_simple_paths(ddg.graph, cl1, cl2), 0, 10000), key=lambda x: len(x))
                if len(local_longest_path) > len(longest_path):
                    longest_path = local_longest_path
                    analysis_results.set_longest_path(longest_path)
                    analysis_results.set_longest_path_len(len(longest_path))

                

        except Exception as e:
            raise e
            errs = [str(e)]
            analysis_results.set_errs(errs)


class DataFlowAnalysisResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.num_nodes = None
        self.num_edges = None
        self.insns_in_ddg_not_cfg = None
        self.insns_in_cfg_not_ddg = None
        self.insns_in_both = None
        self.longest_path = None
        self.longest_path_len = None

        self.errs = []

    def get_num_nodes(self):
        return self.num_nodes
    def set_num_nodes(self, num_nodes):
        self.num_nodes = num_nodes

    def get_num_edges(self):
        return self.num_edges
    def set_num_edges(self, num_edges):
        self.num_edges = num_edges

    def get_insns_in_ddg_not_cfg(self):
        return self.insns_in_ddg_not_cfg
    def set_insns_in_ddg_not_cfg(self, insns_in_ddg_not_cfg):
        self.insns_in_ddg_not_cfg = insns_in_ddg_not_cfg

    def get_insns_in_cfg_not_ddg(self):
        return self.insns_in_cfg_not_ddg
    def set_insns_in_cfg_not_ddg(self, insns_in_cfg_not_ddg):
        self.insns_in_cfg_not_ddg = insns_in_cfg_not_ddg

    def get_insns_in_both(self):
        return self.insns_in_both
    def set_insns_in_both(self, insns_in_both):
        self.insns_in_both = insns_in_both

    def get_longest_path(self):
        return self.longest_path
    def set_longest_path(self, longest_path):
        self.longest_path = longest_path

    def get_longest_path_len(self):
        return self.longest_path_len
    def set_longest_path_len(self, longest_path_len):
        self.longest_path_len = longest_path_len

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['nodes'] = self.num_nodes
        tracked_events['edges'] = self.num_edges
        tracked_events['errs'] = len(self.errs)

        return tracked_events

    def set_errs(self, errs):
        self.errs = errs

    def copy_from_inner(self, other_analysis_results):
        self.set_num_nodes(other_analysis_results.num_nodes)
        self.set_num_edges(other_analysis_results.num_edges)
        self.set_insns_in_ddg_not_cfg(other_analysis_results.insns_in_ddg_not_cfg)
        self.set_insns_in_cfg_not_ddg(other_analysis_results.insns_in_cfg_not_ddg)
        self.set_insns_in_both(other_analysis_results.insns_in_both)
        self.set_longest_path(other_analysis_results.longest_path)
        self.set_longest_path_len(other_analysis_results.longest_path_len)
        for err in other_analysis_results.errs:
            self.add_err(err)

