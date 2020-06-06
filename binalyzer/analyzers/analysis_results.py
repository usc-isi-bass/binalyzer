import abc
from abc import ABC

class AnalysisResults(ABC):

    def add_err(self, err):
        if not hasattr(self, '_errs'):
            self._errs = []
        self._errs.append(err)

    '''
    Tracked events are anything you want to keep track of while analyzing the targets.
    For example, if an error occurred during analysis, you can add 'err':1 to the _tracked_event_dictionary.
    This allows the analyzer to calculate the number of errors that occurred up to the current point in analyzing the targets.
    '''
    @abc.abstractmethod
    def get_tracked_events(self):
        pass

class ErrorAnalysisResults(AnalysisResults):
    
    def __init__(self, err):
        self.add_err(err)

    def get_tracked_events(self):
        return {}
