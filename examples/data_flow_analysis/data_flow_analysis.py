import angr
import sys
import os
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
            cfg = proj.analyses.CFGEmulated(context_sensitivity_level=1, keep_state=True, state_add_options=angr.sim_options.refs)

            main_func = cfg.functions.function(name='main')
            assert main_func is not None, "Could not find \"main\" function"
            main_func_addr = main_func.addr
            ddg = proj.analyses.DDG(cfg, start=main_func_addr)

            num_nodes = len(list(ddg.graph.nodes()))
            num_edges = len(list(ddg.graph.edges()))
            analysis_results.set_num_nodes(num_nodes)
            analysis_results.set_num_edges(num_edges)
        except Exception as e:
            raise e
            errs = [str(e)]
            analysis_results.set_errs(errs)


class DataFlowAnalysisResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.num_nodes = None
        self.num_edges = None

        self.errs = []

    def get_num_nodes(self):
        return self.num_nodes
    def set_num_nodes(self, num_nodes):
        self.num_nodes = num_nodes

    def get_num_edges(self):
        return self.num_edges
    def set_num_edges(self, num_edges):
        self.num_edges = num_edges

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
        for err in other_analysis_results.errs:
            self.add_err(err)

