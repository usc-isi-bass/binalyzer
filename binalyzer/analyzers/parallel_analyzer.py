from abc import ABC


import multiprocessing
import multiprocessing.dummy as threading

from binalyzer.analyzers.analyzer import Analyzer
from binalyzer.analyzers.analysis_results import ErrorAnalysisResults

class ParallelAnalyzer(Analyzer):

    def __init__(self, analysis, **analysis_options):
        if 'nthreads' in analysis_options:
            nthreads = analysis_options.pop('nthreads')
        else:
            nthreads = 1
        Analyzer.__init__(self, analysis, **analysis_options)
        self._nthreads = nthreads

    def analyze_targets(self, analysis_targets):
        with threading.Pool(self._nthreads) as pool:
            for analysis_target, analysis_results in pool.imap_unordered(self.analyze_target, analysis_targets):
                yield analysis_target, analysis_results



