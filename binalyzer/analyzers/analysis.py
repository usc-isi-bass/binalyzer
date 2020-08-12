import abc
from abc import ABC

from binalyzer.target_discovery.analysis_target import AnalysisTarget

class Analysis(ABC):
    '''
    An abstract class for an analysis.
    '''

    @abc.abstractmethod
    def analyze(self, analysis_target: AnalysisTarget):
        '''Apply the analysis to analysis_target

        Parameters
        ----------
        analysis_target : AnalysisTarget
            An AnalysisTarget object containing the information of the target to analyze

        Returns
        -------
        AnalysisResults
            The results of the analysis stored in an AnalysisResults object


        '''
        pass

    @abc.abstractmethod
    def results_constructor(self):
        '''Returns the constructor for creating the analysis results object. A blank instance will be passed to analyze where the properties should be populated.
        '''
        pass
