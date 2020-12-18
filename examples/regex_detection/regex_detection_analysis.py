import sys
import os
import logging
import networkx as nx

import angr
import pyvex

import re

logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

CLOSURE_REGEX = re.compile(r'\*|\+|(?:\{\d+,\})') # To detect closure operations in potential regexes
UNION_REGEX = re.compile(r'\|') # To detect the union operation in potential regexes
FMT_STR_REGEX = re.compile(r'%(?:\d+\$)?(\d*)(?:f|d|c|s|x)') # To detect probable format strings

class RegexDetectionAnalysis(Analysis):

    def __init__(self, minimum_str_len, cached_results_path=None):
        super().__init__(cached_results_path)
        self._minimum_str_len = minimum_str_len

    def results_constructor(self):
        return RegexDetectionAnalysisResults

    def analyze(self, analysis_target, analysis_results):
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast(data_references=True, cross_references=True, normalize=True)

            for func_addr, func in cfg.functions.items():
                if func.is_plt or func.is_simprocedure:
                    continue
                # Because angr is buggy, vex_only=False does not return all strings
                addr_strings = set(list(func.string_references(minimum_length=self._minimum_str_len, vex_only=False)) + list(func.string_references(minimum_length=self._minimum_str_len, vex_only=True)))

                call_sites = func.get_call_sites()

                # str_addr is the adress of the string. not the insn that accesses the string
                for str_addr, string in addr_strings:

                    if not self.string_is_regex(string):
                        continue

                    for xref in self.find_xrefs_to_str(cfg, func, str_addr):
                        insn_addr = xref.ins_addr
                        dst_addr = xref.dst
                        block_addr = xref.block_addr
                        mem_data = xref.memory_data

                        assert str_addr == mem_data.address == dst_addr, "Logic error: I assumed these should be equal: addr: {} mem_data.address: {} dst_addr: ".format(str_addr, mem_data.address, dst_addr)

                        called_func_name, called_func_addr = None, None
                        if block_addr in call_sites:
                            call_target = func.get_call_target(block_addr)
                            called_func = cfg.functions.function(addr=call_target)

                            if called_func is None:
                                # Why would angr do this?
                                called_func_name, called_func_addr = '?', call_target
                            else:
                                called_func_name, called_func_addr = called_func.name, called_func.addr


                        detected_regex = DetectedRegex(string, str_addr, insn_addr, block_addr, func.name, func_addr, called_func_name, called_func_addr)
                        analysis_results.add_detected_regex(detected_regex)




                    
                    
            

        except Exception as e:
            #raise e
            analysis_results.add_err(str(e))

    def string_is_regex(self, string):
        if '\n' in string or '\t' in string:
            return False

        # To reduce the number of strings we find, we search only for regexes with either groups (() or character classes ([)
        if not ('[' in string or '(' in string):
            return False

        # If it does not contain a operator allowing for unlimited length input strings, we do not care
        if CLOSURE_REGEX.search(string) is None:
            return False

        # It is most probably a format string
        if FMT_STR_REGEX.search(string) is not None:
            return False
        try:
            # Check if we can compile the string to see if its a valid regex
            test_regex = re.compile(string)
            return True
        except re.error:
            return False

    def find_xrefs_to_str(self, cfg, func, str_addr):
        for block_addr in func.block_addrs:
            node = cfg.model.get_any_node(addr=block_addr)
            for xref in filter(lambda xref: xref.dst == str_addr, node.accessed_data_references):
                yield xref

class RegexDetectionAnalysisResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.detected_regexes = []
        self.errs = []


    def set_detected_regexes(self, detected_regexes):
        self.detected_regexes = detected_regexes[::]

    def add_detected_regex(self, detected_regex):
        self.detected_regexes.append(detected_regex)

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['errs'] = len(self.errs)
        tracked_events['regexes'] = len(self.detected_regexes)

        return tracked_events

    def add_err(self, err):
        self.errs.append(err)

    def copy_from_inner(self, other_analysis_results):

        for detected_regex in other_analysis_results.detected_regexes:
            self.add_detected_regex(detected_regex)
        for err in other_analysis_results.errs:
            self.add_err(err)

class DetectedRegex:

    def __init__(self, regex_str, regex_str_addr, insn_addr, insn_block_addr, func_name, func_addr, called_func_name, called_func_addr):
        self.regex_str = regex_str
        self.regex_str_addr = regex_str_addr
        self.insn_addr = insn_addr
        self.insn_block_addr = insn_block_addr
        self.func_name = func_name
        self.func_addr = func_addr
        self.called_func_name = called_func_name # Should be (called_func_name, called_func_addr) if insn_block_addr is a call site in func else None
        self.called_func_addr = called_func_addr
