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

from binalyzer.target_discovery.elf_discoverer import ElfDiscovererSearch,ElfDiscovererListFile,ElfDiscovererList
from binalyzer.target_discovery.analysis_target import AnalysisTarget


from binalyzer.result_storage.result_storer import ResultStorer

TIME_FORMAT = "%H:%M:%S, %9A, %d-%m-%Y"

class Analyzer(ABC):
    '''
    A class to run an Analysis on a number of a number of AnalysisTargets
    '''

    def __init__(self, analysis: Analysis, root_dir: str=None, elf_list: list=None, elf_list_file: str=None, break_limit: int=None, remove_duplicates: bool=True, results_path: str=os.getcwd(), timeout: int=None):
        '''
        Parameters
        ----------
        analysis : Analysis
            An object of a type that implements the interface Analysis
        root_dir : str
            The root directory from where the search for analysis targets will start. (mutually exclusive with elf_list_file and elf_list)
        elf_list : list
            A list of strings specifying the file names of the analysis targets. (mutually exclusive with root_dir and elf_list_file)
        elf_list_file : str
            A file containing a list of strings specifying the file names of the analysis targets. (mutually exclusive with root_dir and elf_list)
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
        self._elf_list_file = elf_list_file
        self._break_limit = break_limit
        self._remove_duplicates = remove_duplicates
        self._results_path = results_path
        self._timeout = timeout

        target_sources = [self._root_dir, self._elf_list_file, self._elf_list]

        if sum([int(src is not None) for src in target_sources]) != 1:
            raise Exception("Invalid analyzer options: You must specify exactly one of root, elf_list, or elf_list_file. We received: {}".format(target_sources))

        self._target_generator = None
        if self._root_dir is not None:
            self._target_generator = ElfDiscovererSearch(self._root_dir, remove_duplicates=self._remove_duplicates, break_limit=self._break_limit)
        elif self._elf_list is not None:
            self._target_generator = ElfDiscovererList(self._elf_list, remove_duplicates=self._remove_duplicates, break_limit=self._break_limit)
        elif self._elf_list_file is not None:
            self._target_generator = ElfDiscovererListFile(self._elf_list_file, remove_duplicates=self._remove_duplicates, break_limit=self._break_limit)
        assert self._target_generator is not None, "No target generator created for analyzer"

        self._full_results_file_path = None
        if os.path.isdir(self._results_path):
            results_file_name = "results_{}".format(time.strftime("%Y%m%d_%0H%0M%0S"))
            self._full_results_file_path = os.path.abspath(os.path.join(self._results_path, results_file_name))
        else:
            self._full_results_file_path = os.path.abspath(self._results_path)

        results = self._analysis.results_constructor()
        multiprocessing.managers.BaseManager.register('AnalysisResults', results)
        self._manager = multiprocessing.managers.BaseManager()
        self._manager.start() # TODO we probably have to shut this down somewhere...
            


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
        analysis_results = self._manager.AnalysisResults()

        # Spawn a new process for the analysis so we can timeout it.
        timeout_occurred = False
        p = multiprocessing.Process(target=self._analysis.get_cache_or_analyze, args=(analysis_target, analysis_results))
        start_time = datetime.datetime.now()
        p.start()
        if self._timeout is not None:
            p.join(timeout=self._timeout)
        else:
            p.join()
        time.sleep(0.005)
        if p.is_alive():
            timeout_occurred = True
            while p.is_alive():
                p.terminate()
                p.join()
        p.close()
        end_time = datetime.datetime.now()
        analysis_results = analysis_results._getvalue()
        #manager.shutdown()

        # If the results were cached, use the cached times instead
        if analysis_results.get_cached_from() is None:
            analysis_results.set_start_time(start_time)
            analysis_results.set_end_time(end_time)
        if timeout_occurred:
            analysis_results.add_err('timeout')
        
        # We return the analsis target, because for multiprocessed analyzers we cannot be sure which results belong to which input
        return analysis_target, analysis_results

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
                self.log_progress(global_start_time, i + 1, analysis_targets_len, analysis_result, tracked_result_events)

        # Print newline so we don't overwrite last log
        print("")

        print("Results saved to: {}".format(self._full_results_file_path))

        global_end_time = time.localtime()
        global_run_time = self.format_time_delta(global_start_time, global_end_time)
        print("Finished: {}".format(time.strftime(TIME_FORMAT, global_end_time)))
        print("Total time: {}".format(global_run_time))

                




            

    def log_progress(self, start_time, completed, total, analysis_result, tracked_result_events):
        time_str = "{:%d %b %Y %H:%M:%S}".format(datetime.datetime.now())


        for tracked_event, tracked_event_val in analysis_result.get_tracked_events().items():
            if tracked_event_val is None:
                continue
            if tracked_event in tracked_result_events:
                tracked_result_events[tracked_event] += tracked_event_val
            else:
                tracked_result_events[tracked_event] = tracked_event_val
            
        time_remaining_s = self.calculate_eta_s(completed, total, start_time)
        time_remaining_str = self.format_time_seconds(time_remaining_s, short=True)
        print("{}/{} elfs {} | {} (eta: {})".format(completed, total, tracked_result_events, time_str, time_remaining_str), flush=True, end='\r')

    def format_time_delta(self, start_time, end_time, short=False):
        time_delta_datetime = self.calculate_time_delta(start_time, end_time)
        seconds = int(time_delta_datetime.total_seconds())
        return self.format_time_seconds(seconds, short)

    def format_time_seconds(self, seconds, short=False):
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        if short:
                return "{0}:{1:02d}:{2:02d}:{3:02d}".format(days, hours, minutes, seconds)
        else:
                return "{0} days, {1} hours, {2:02d} minutes and {3:02d} seconds.".format(days, hours, minutes, seconds)


    # Returns number of seconds remaining
    def calculate_eta_s(self, completed, total, start_time):
        current_time = time.localtime()
        duration = self.calculate_time_delta(start_time, current_time)
        duration_s = duration.total_seconds()

        # We finished "completed" in "duration_s" seconds
        duration_per_one_s = float(duration_s) / float(completed)

        num_remaining = float(total - completed)
        duration_remaining_s = num_remaining * duration_per_one_s

        return int(round(duration_remaining_s))

    def calculate_time_delta(self, t1, t2):
        t1_datetime = datetime.datetime.fromtimestamp(time.mktime(t1))
        t2_datetime = datetime.datetime.fromtimestamp(time.mktime(t2))
        time_delta_datetime = t2_datetime - t1_datetime
        return time_delta_datetime
        

