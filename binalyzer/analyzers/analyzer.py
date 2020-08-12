import abc
from abc import ABC

import os
import datetime
import time
import json
import signal

import multiprocessing
import multiprocessing.managers

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults
from binalyzer.analyzers.analysis_results import ErrorAnalysisResults

from binalyzer.target_discovery.elf_discoverer import ElfDiscovererSearch,ElfDiscovererList
from binalyzer.target_discovery.analysis_target import AnalysisTarget


from binalyzer.result_storage.result_storer import ResultStorer

TIME_FORMAT = "%H:%M:%S, %9A, %d-%m-%Y"

class Analyzer(ABC):
    '''
    A class to run an Analysis on a number of a number of AnalysisTargets
    '''

    def __init__(self, analysis: Analysis, root_dir: str=None, elf_list: list=None, break_limit: int=None, remove_duplicates: bool=True, results_path: str=os.getcwd(), timeout: int=None):
        '''
        Parameters
        ----------
        analysis : Analysis
            An object of a type that implements the interface Analysis
        root_dir : str
            The root directory from where the search for analysis targets will start. (mutually exclusive with elf_list)
        elf_list : list
            A list of strings specifying the file names of the analysis targets. (mutually exclusive with root_dir)
        break_limit : int
            An upper bound on the number of AnalysisTargets to generate
        remove_duplicates : bool
            Ensure all AnalysisTargets have a unique MD5 hash
        results_path : str
            Either a directory or a filename. If a directory, the analysis results will be stored in a file in this directory (the file name will be the time the analysis started).
            If a filename, the analysis results will be stored in this file.
            The default is the current working directory.
        timeout : int
            The number of seconds after which the analysis of a single AnalysisTarget will be stopped.
        '''
        self._analysis = analysis
        self._root_dir = root_dir
        self._elf_list = elf_list
        self._break_limit = break_limit
        self._remove_duplicates = remove_duplicates
        self._results_path = results_path
        self._timeout = timeout

        if not ((self._root_dir is not None) ^ (self._elf_list is not None)):
            raise Exception("Invalid analysis options: You must specify exactly one of root or elf_list")

        self._target_generator = None
        if self._root_dir is not None:
            self._target_generator = ElfDiscovererSearch(self._root_dir, break_limit=self._break_limit)
        elif self._elf_list is not None:
            self._target_generator = ElfDiscovererList(self._elf_list, break_limit=self._break_limit)

        self._full_results_file_path = None
        if os.path.isdir(self._results_path):
            results_file_name = "results_{}".format(time.strftime("%Y%m%d_%0H%0M%0S"))
            self._full_results_file_path = os.path.abspath(os.path.join(self._results_path, results_file_name))
        else:
            self._full_results_file_path = os.path.abspath(self._results_path)

        results = self._analysis.results_constructor()
        multiprocessing.managers.BaseManager.register('AnalysisResults', results)
            
            


    @abc.abstractmethod
    def analyze_targets(self, analysis_targets: list):
        '''
        Apply analyze_target to each of the AnalysisTargets

        Parameters
        ----------
        analysis_targets : list
            A list of AnalysisTargets to analyze.

        Returns
        -------
        (AnalysisTarget, AnalysisResult)
            Return a pair of the target of analysis and its result
        '''
        pass


    def analyze_target(self, analysis_target: AnalysisTarget):
        '''
        Start a process and run the Analysis on analysis_target.
        The amount of time specified in the timeout parameter of the Analyzer is waited before the process is terminated.

        Parameters
        ----------
        analsis_target : AnalysisTarget
            The target to analyze
        Returns
        -------
        (AnalysisTarget, AnalysisResult)
            Return a pair of the target of analysis and its result
        '''
        manager = multiprocessing.managers.BaseManager()
        manager.start()
        analysis_results = manager.AnalysisResults()

        # Spawn a new process for the analysis so we can timeout it.
        timeout_occurred = False
        p = multiprocessing.Process(target=self.wrap_analyze_target, args=(analysis_target, analysis_results))
        start_time = datetime.datetime.now()
        p.start()
        if self._timeout is not None:
            p.join(timeout=self._timeout)
        else:
            p.join()
        if p.is_alive():
            timeout_occurred = True
            p.terminate()
            p.join()
        end_time = datetime.datetime.now()
        analysis_results = analysis_results._getvalue()
        manager.shutdown()
        #if 'results' in results_dict:
        #    analysis_results = results_dict['results']
        #
        #else:
        #    # If this happens, an uncaught exception may have occurred that prevented your analysis from returning.
        #    # Try to catch all exceptions and at least return something
        #    analysis_results = ErrorAnalysisResults("The analysis did not return any results.")

        analysis_results.start_time = start_time
        analysis_results.end_time = end_time
        if timeout_occurred:
            analysis_results.add_err('timeout')
        
        # We return the analsis target, because for multiprocessed analyzers we cannot be sure which results belong to which input
        return analysis_target, analysis_results


    def wrap_analyze_target(self, analysis_target, analysis_results):
        self._analysis.analyze(analysis_target, analysis_results)


    def run_analysis(self):
        '''
        Start running the analysis.
        '''
        analysis_targets = []
        print("Generating targets:")
        for i, analysis_target in enumerate(self._target_generator.find_targets()):
            print("Generated {} targets".format(i + 1), end='\r', flush=True)
            analysis_targets.append(analysis_target)

        print("Generated {} targets".format(len(analysis_targets)), end='\r', flush=True)

        # TODO Implement the option for a user to specify a cached results file and remove the targets with cached results from the analysis_targets list

        analysis_targets_len = len(analysis_targets)
        print("Analyzing {} elfs".format(analysis_targets_len), end='\r', flush=True)

        global_start_time = time.localtime()
        print("Analysis started on: {}".format(time.strftime(TIME_FORMAT, global_start_time)))

        tracked_result_events = {}
        print("Saving results to {}".format(self._full_results_file_path))
        with ResultStorer(self._full_results_file_path) as result_storer:
            i, analysis_result = 0, None # For if someone runs with no analysis targets
            for i, (analysis_target, analysis_result) in enumerate(self.analyze_targets(analysis_targets)):
                result_storer.store(analysis_target, analysis_result)
                self.log_progress(i + 1, analysis_targets_len, analysis_result, tracked_result_events)

        # Print newline so we don't overwrite last log
        print("")

        print("Results saved to: {}".format(self._full_results_file_path))

        global_end_time = time.localtime()
        global_run_time = self.format_time_delta(global_start_time, global_end_time)
        print("Finished: {}".format(time.strftime(TIME_FORMAT, global_end_time)))
        print("Total time: {}".format(global_run_time))

                
            

    def log_progress(self, completed, total, analysis_result, tracked_result_events):
        time_str = "{:%d %b %Y %H:%M:%S}".format(datetime.datetime.now())


        for tracked_event, tracked_event_val in analysis_result.get_tracked_events().items():
            if tracked_event_val is None:
                continue
            if tracked_event in tracked_result_events:
                tracked_result_events[tracked_event] += tracked_event_val
            else:
                tracked_result_events[tracked_event] = tracked_event_val
            
        print("{}/{} elfs {} | {}".format(completed, total, tracked_result_events, time_str), flush=True, end='\r')

    def format_time_delta(self, start_time, end_time, short=False):
        start_time_datetime = datetime.datetime.fromtimestamp(time.mktime(start_time))
        end_time_datetime = datetime.datetime.fromtimestamp(time.mktime(end_time))
        time_delta_datetime = end_time_datetime - start_time_datetime
        seconds = int(time_delta_datetime.total_seconds())
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        if short:
                return "{0}:{1:02d}:{2:02d}:{3:02d}".format(days, hours, minutes, seconds)
        else:
                return "{0} days, {1} hours, {2:02d} minutes and {3:02d} seconds.".format(days, hours, minutes, seconds)
        

