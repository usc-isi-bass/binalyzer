import abc
from abc import ABC

import os
import datetime
import time
import json

import multiprocessing

from binalyzer.target_discovery.elf_discoverer import ElfDiscovererSearch,ElfDiscovererList

from binalyzer.result_storage.result_storer import ResultStorer

TIME_FORMAT = "%H:%M:%S, %9A, %d-%m-%Y"

class Analyzer(ABC):

    def __init__(self, analysis, root_dir=None, elf_list=None, break_limit=None, remove_duplicates=True, results_path=os.getcwd(), timeout=None):
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
            self._full_results_file_path = os.path.join(self._results_path, results_file_name)
        else:
            self._full_results_file_path = self._results_path
            
            


    @abc.abstractmethod
    def analyze_targets(self, analysis_targets):
        pass


    def analyze_target(self, analysis_target):
        results_dict = multiprocessing.Manager().dict()

        # Spawn a new process for the analysis so we can timeout it.
        timeout_occurred = False
        p = multiprocessing.Process(target=self.wrap_analyze_target, args=(analysis_target, results_dict))
        p.start()
        if self._timeout is not None:
            p.join(timeout=self._timeout)
        else:
            p.join()
        if p.is_alive():
            timeout_occurred = True
            p.terminate()
            p.join()
        analysis_results = None
        if 'results' in results_dict:
            analysis_results = results_dict['results']
        
        else:
            # If this happens, an uncaught exception may have occurred that prevented your analysis from returning.
            # Try to catch all exceptions and at least return something
            analysis_results = ErrorAnalysisResults("The analysis did not return any results.")

        if timeout_occurred:
            analysis_results.add_err('timeout')
        
        # We return the analsis target, because for multiprocessed analyzers we cannot be sure which results belong to which input
        return analysis_target, analysis_results


    def wrap_analyze_target(self, analysis_target, results_dict):
        analysis_results = self._analysis.analyze(analysis_target)
        results_dict['results'] = analysis_results


    def run_analysis(self):
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
            for i, (analysis_target, analysis_result) in enumerate(self.analyze_targets(analysis_targets)):
                result_storer.store(analysis_target, analysis_result)
                self.log_progress(i + 1, analysis_targets_len, analysis_result, tracked_result_events, done=False)

        self.log_progress(i + 1, analysis_targets_len, analysis_result, tracked_result_events, done=True)

        print("Results saved to: {}".format(self._full_results_file_path))

        global_end_time = time.localtime()
        global_run_time = self.format_time_delta(global_start_time, global_end_time)
        print("Finished: {}".format(time.strftime(TIME_FORMAT, global_end_time)))
        print("Total time: {}".format(global_run_time))

                
            

    def log_progress(self, completed, total, analysis_result, tracked_result_events, done=False):
        time_str = "{:%d %b %Y %H:%M:%S}".format(datetime.datetime.now())
        if done:
            end='\r\n'
        else:
            end='\r'

        for tracked_event, tracked_event_val in analysis_result.get_tracked_events().items():
            if tracked_event in tracked_result_events:
                tracked_result_events[tracked_event] += tracked_event_val
            else:
                tracked_result_events[tracked_event] = tracked_event_val
            
        print("{}/{} elfs {} | {}".format(completed, total, tracked_result_events, time_str), end=end)

    def format_time_delta(self, start_time, end_time, short=False):
        start_time_datetime = datetime.datetime.fromtimestamp(time.mktime(start_time))
        end_time_datetime = datetime.datetime.fromtimestamp(time.mktime(end_time))
        time_delta_datetime = end_time_datetime - start_time_datetime
        seconds = int(time_delta_datetime.seconds)
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        if short:
                return "{0}:{1:02d}:{2:02d}:{3:02d}".format(days, hours, minutes, seconds)
        else:
                return "{0} days, {1} hours, {2:02d} minutes and {3:02d} seconds.".format(days, hours, minutes, seconds)
        
