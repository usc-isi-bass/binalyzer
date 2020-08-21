import angr
import sys
import os
import logging

logging.getLogger('cle').setLevel(logging.CRITICAL)

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

class CountFunctionsAnalysis(Analysis):

    def results_constructor(self):
        return CountFunctionsAnalysisResults
    
    def analyze(self, analysis_target, analysis_results):
        num_funcs = None
        errs = []
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)
            funcs = cfg.functions.items()
            num_funcs = len(funcs)
            analysis_results.set_num_funcs(num_funcs)
        except Exception as e:
            errs = [str(e)]
            analysis_results.errs = errs

        #return CountFunctionsAnalysisResults(num_funcs, errs)

class CountFunctionsAnalysisResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.num_funcs = None
        self.errs = []

    def get_num_funcs(self):
        return self.num_funcs
    def set_num_funcs(self, num_funcs):
        self.num_funcs = num_funcs

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['num_funcs'] = self.num_funcs
        tracked_events['errs'] = len(self.errs)

        return tracked_events
