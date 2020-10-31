import angr
import sys
import os
import logging

logging.getLogger('cle').setLevel(logging.CRITICAL)

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

class SortFuncDetectionAnalysis(Analysis):

    def results_constructor(self):
        return SortFuncDetectionAnalysisResults

    def analyze(self, analysis_target, results):
        num_funcs = None
        errs = []
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)
            for func_addr, func in cfg.functions.items():
                func_name = func.name
                if 'sort' in func_name.lower():
                    is_recursive = self.is_func_recursive(func)
                    is_plt = func.is_plt
                    discovered_sort_func = DiscoveredSortFunc(func_name, func_addr, is_recursive, is_plt)
                    results.add_discovered_sort_func(discovered_sort_func)
        except Exception as e:
            #raise e
            results.add_err(str(e))
            errs = [str(e)]
            analysis_results.errs = errs

    # Only checks if a function calls itself
    def is_func_recursive(self, func):
        func_addr = func.addr
        for call_site_addr in func.get_call_sites():
            call_target_addr = func.get_call_target(call_site_addr)
            if call_target_addr == func_addr:
                return True
        return False
            

class SortFuncDetectionAnalysisResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.discovered_sort_funcs = []
        self.errs = []


    def add_discovered_sort_func(self, discovered_sort_func):
        self.discovered_sort_funcs.append(discovered_sort_func)

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['sorts'] = len(self.discovered_sort_funcs)
        tracked_events['errs'] = len(self.errs)

        return tracked_events

    def copy_from_inner(self, other_analysis_results):
        for discovered_sort_func in other_analysis_results.discovered_sort_funcs:
            self.add_discovered_sort_func(discovered_sort_func)
        for err in other_analysis_results.errs:
            self.add_err(err)


class DiscoveredSortFunc:

    def __init__(self, func_name, func_addr, is_recursive, is_plt):
        self.func_name = func_name
        self.func_addr = func_addr
        self.recursive = is_recursive
        self.is_plt = is_plt
