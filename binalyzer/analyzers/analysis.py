import os
import sys
import abc
from abc import ABC

from binalyzer.target_discovery.analysis_target import AnalysisTarget
from binalyzer.analyzers.analysis_results import AnalysisResults

from binalyzer.result_storage.result_reader import ResultReader

class Analysis(ABC):
    '''
    An abstract class for an analysis.
    '''

    def __init__(self, cached_results_path: str=None):
        '''
        Parameters
        ----------
        cached_results_path : str
            A filename containing the analysis results that should be used as a cache.
        '''

        self._cached_results_path = cached_results_path
        self._results_cache = {}
        if self._cached_results_path is not None:
            self._build_cache(self._cached_results_path)

    def get_cache_or_analyze(self, analysis_target: AnalysisTarget, analysis_results: AnalysisResults):
        file_md5 = analysis_target.file_md5
        if file_md5 not in self._results_cache:
            self.analyze(analysis_target, analysis_results)
            self._results_cache[file_md5] = analysis_results
        else:
            cached_analysis_results = self._results_cache[file_md5]
            analysis_results.copy_from(cached_analysis_results)
            if analysis_results.get_cached_from() is None and self._cached_results_path is not None:
                analysis_results.set_cached_from(os.path.basename(self._cached_results_path))


    @abc.abstractmethod
    def analyze(self, analysis_target: AnalysisTarget, analysis_results: AnalysisResults):
        '''Apply the analysis to analysis_target

        Parameters
        ----------
        analysis_target : AnalysisTarget
            An AnalysisTarget object containing the information of the target to analyze
        AnalysisResults
            An empty AnalysisResults object where the results will be stored during analysis


        '''
        pass

    @abc.abstractmethod
    def results_constructor(self):
        '''Returns the constructor for creating the analysis results object. A blank instance will be passed to analyze where the properties should be populated.
        '''
        pass


    def _build_cache(self, cached_results_path):
        dummy_results = self.results_constructor()
        with ResultReader(cached_results_path) as result_reader:
            for result_storage_unit in result_reader.read():
                analysis_target = result_storage_unit.analysis_target
                analysis_results = result_storage_unit.analysis_results
                assert type(analysis_results) == dummy_results, "We have cached results of type {}, but this analysis generates results of type {}".format(type(analysis_results), dummy_results)
                file_md5 = analysis_target.file_md5
                if file_md5 in self._results_cache:
                    print("WARN: We already have cached results for: {} (MD5: {})".format(analysis_target.file_name, file_md5), file=sys.stderr)

                self._results_cache[file_md5] = analysis_results
