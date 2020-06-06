import angr
import sys
import os
import logging

logging.getLogger('cle').setLevel(logging.CRITICAL)

# Because apparently python only adds the parent directory of the running script to the PATH.
# We want the parent of the parent to be added, because that's where input_dependence ans hash_table_discovery is
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

class CountFunctionsAnalysis(Analysis):
    
    def analyze(self, analysis_target):
        num_funcs = None
        errs = []
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast()
            num_funcs = len(cfg.functions.items())
        except Exception as e:
            errs = [str(e)]

        return CountFunctionsAnalysisResults(num_funcs, errs)

class CountFunctionsAnalysisResults(AnalysisResults):
    def __init__(self, num_funcs, errs):
        AnalysisResults.__init__(self)
        self.num_funcs = num_funcs
        self.errs = errs

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['num_funcs'] = self.num_funcs
        tracked_events['errs'] = len(self.errs)

        return tracked_events
