import argparse
import sys
import os
import logging

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False
logging.getLogger('claripy').disabled = True
logging.getLogger('claripy').propagate = False
logging.getLogger('pyvex').disabled = True
logging.getLogger('pyvex').propagate = False

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.sequential_analyzer import SequentialAnalyzer
from binalyzer.analyzers.parallel_analyzer import ParallelAnalyzer
from binalyzer.util.analyzer_argument_parser import ParallelAnalyzerArgumentParser

from indirect_control_flow_detection_analysis import IndirectControlFlowDetectionAnalysis

def main():
    analyzer_argument_parser = ParallelAnalyzerArgumentParser()
    parser = argparse.ArgumentParser('Analyze the indirect jumps/calls in a program', parents=[analyzer_argument_parser])

    args = parser.parse_args()
    root_dir = args.root_dir
    elf_list = args.elf_list
    elf_list_file = args.elf_list_file
    break_limit = args.break_limit
    remove_duplicates = args.remove_duplicates
    results_path = args.results_path
    cached_results_path = args.cached_results
    timeout = args.timeout
    nthreads = args.nthreads

    analysis = IndirectControlFlowDetectionAnalysis(cached_results_path=cached_results_path)
    analyzer = ParallelAnalyzer(analysis, root_dir=root_dir, elf_list=elf_list, elf_list_file=elf_list_file, break_limit=break_limit, remove_duplicates=remove_duplicates, results_path=results_path, timeout=timeout, nthreads=nthreads)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()

