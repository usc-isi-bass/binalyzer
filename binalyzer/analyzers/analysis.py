import abc
from abc import ABC

class Analysis(ABC):

    '''
    Should return something that implements AnalysisResults
    '''
    @abc.abstractmethod
    def analyze(self, analysis_target):
        pass
