import angr
import sys
import os
import logging

logging.getLogger('cle').setLevel(logging.CRITICAL)

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

class IndirectControlFlowDetectionAnalysis(Analysis):

    def results_constructor(self):
        return IndirectControlFlowDetectionAnalysisResults

    def analyze(self, analysis_target, analysis_results):
        num_indirect_jumps = 0
        num_indirect_calls = 0
        num_indirect_others = 0
        errs = []
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)
            for uij in proj.kb.unresolved_indirect_jumps:
                node = cfg.model.get_any_node(addr=uij, anyaddr=True)
                assert node is not None, "Could not find node for addr: {}".format(uij)
                succ_nodes = cfg.model.get_successors(node, excluding_fakeret=True)
                for succ_node in succ_nodes:
                    if succ_node.simprocedure_name == 'UnresolvableJumpTarget':
                        num_indirect_jumps += 1
                    elif succ_node.simprocedure_name == 'UnresolvableCallTarget':
                        num_indirect_calls += 1
                    else:
                        num_indirect_others += 1
            analysis_results.set_num_indirect_jumps(num_indirect_jumps)
            analysis_results.set_num_indirect_calls(num_indirect_calls)
            analysis_results.set_num_indirect_others(num_indirect_others)
        except Exception as e:
            errs = [str(e)]
            analysis_results.errs = errs


class IndirectControlFlowDetectionAnalysisResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.num_indirect_jumps = None
        self.num_indirect_calls = None
        self.num_indirect_others = None
        self.errs = []

    def get_num_indirect_jumps(self):
        return self.num_indirect_jumps
    def set_num_indirect_jumps(self, num_indirect_jumps):
        self.num_indirect_jumps = num_indirect_jumps
    def get_num_indirect_calls(self):
        return self.num_indirect_calls
    def set_num_indirect_calls(self, num_indirect_calls):
        self.num_indirect_calls = num_indirect_calls
    def get_num_indirect_others(self):
        return self.num_indirect_others
    def set_num_indirect_others(self, num_indirect_others):
        self.num_indirect_others = num_indirect_others

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['num_indirect_jumps'] = self.num_indirect_jumps
        tracked_events['num_indirect_calls'] = self.num_indirect_calls
        tracked_events['num_indirect_others'] = self.num_indirect_others
        tracked_events['errs'] = len(self.errs)

        return tracked_events

    def copy_from_inner(self, other_analysis_results):

        self.set_num_indirect_jumps(other_analysis_results.num_indirect_jumps)
        self.set_num_indirect_calls(other_analysis_results.num_indirect_calls)
        self.set_num_indirect_others(other_analysis_results.num_indirect_others)
        for err in other_analysis_results.errs:
            self.add_err(err)

