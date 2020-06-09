import abc
from abc import ABC

from binalyzer.target_discovery.analysis_target import AnalysisTarget

class Analysis(ABC):

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
