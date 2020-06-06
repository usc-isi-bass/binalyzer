import abc
from abc import ABC

from binalyzer.analyzers.analyzer import Analyzer

class SequentialAnalyzer(Analyzer):

    def analyze_targets(self, analysis_targets):
        for analysis_target in analysis_targets:
            analysis_results, analysis_results = self.analyze_target(analysis_target)
            yield analysis_target, analysis_results


