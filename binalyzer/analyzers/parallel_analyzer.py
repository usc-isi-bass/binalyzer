from abc import ABC


import multiprocessing
import concurrent
import multiprocessing.dummy as threading

import pebble

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

        manager = multiprocessing.managers.BaseManager()
        manager.start()
        analysis_results_objects = [manager.AnalysisResults() for i in range(len(analysis_targets))]
        args = zip(analysis_targets, analysis_results_objects)
        with pebble.ProcessPool(self._nthreads) as pool:
            future = pool.map(self.analyze_target, args, timeout=self._timeout)
            args = zip(analysis_targets, analysis_results_objects)
            map_iter = future.result()
            while True:
                try:
                    analysis_target, analysis_results = next(args)
                    analysis_target, analysis_results = next(map_iter)
                except StopIteration:
                    break
                except concurrent.futures.TimeoutError:
                    analysis_results.add_err('timeout')
                analysis_results = analysis_results._getvalue()
                yield analysis_target, analysis_results
        manager.shutdown()




