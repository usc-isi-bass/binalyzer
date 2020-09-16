import argparse
import sys
import os

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.sequential_analyzer import SequentialAnalyzer
from binalyzer.analyzers.parallel_analyzer import ParallelAnalyzer
from binalyzer.util.analyzer_argument_parser import ParallelAnalyzerArgumentParser

from count_functions_analysis import CountFunctionsAnalysis

def main():
    analyzer_argument_parser = ParallelAnalyzerArgumentParser()
    parser = argparse.ArgumentParser('Count the number of functions in binaries.', parents=[analyzer_argument_parser])
    parser.add_argument('--cached_results', type=str, required=False, help="A filename containing cached results.")

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

    if results_path is None:
        results_path = './example_sequential_analysis_results'

    analysis = CountFunctionsAnalysis()
    print("Sequential analysis:")
    seq_analyzer = SequentialAnalyzer(analysis, root_dir=root_dir, elf_list=elf_list, elf_list_file=elf_list_file, break_limit=break_limit, remove_duplicates=remove_duplicates, results_path=results_path, cached_results_path=cached_results_path, timeout=timeout)
    seq_analyzer.run_analysis()

    if results_path == 'example_sequential_analysis_results':
        results_path = './example_parallel_analysis_results'

    print("Parallel analysis:")
    par_analyzer = ParallelAnalyzer(analysis, root_dir=root_dir, elf_list=elf_list, elf_list_file=elf_list_file, break_limit=break_limit, remove_duplicates=remove_duplicates, results_path=results_path, cached_results_path=cached_results_path, timeout=timeout, nthreads=nthreads)
    par_analyzer.run_analysis()

if __name__ == "__main__":
    main()

