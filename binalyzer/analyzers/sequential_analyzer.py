import abc
from abc import ABC
import multiprocessing
import multiprocessing.managers

from binalyzer.analyzers.analyzer import Analyzer

class SequentialAnalyzer(Analyzer):

    def analyze_targets(self, analysis_targets):
        with multiprocessing.managers.BaseManager() as manager:
            analysis_results_objects = [manager.AnalysisResults() for i in range(len(analysis_targets))]
            args = zip(analysis_targets, analysis_results_objects)
            for analysis_target, analysis_result in map(self.analyze_target, args):
                    yield analysis_target, analysis_result


