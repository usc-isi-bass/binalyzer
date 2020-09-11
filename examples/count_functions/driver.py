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

    args = parser.parse_args()
    root_dir = args.root_dir
    elf_list_file = args.elf_list_file
    break_limit = args.break_limit
    nthreads = args.nthreads
    
    analysis = CountFunctionsAnalysis()
    print("Sequential analysis:")
    seq_analyzer = SequentialAnalyzer(analysis, root_dir=root_dir, elf_list_file=elf_list_file, break_limit=break_limit, results_path='./example_sequential_analysis_results')
    seq_analyzer.run_analysis()
    print("Parallel analysis:")
    par_analyzer = ParallelAnalyzer(analysis, root_dir=root_dir, elf_list_file=elf_list_file, nthreads=nthreads, break_limit=break_limit, results_path='./example_parallel_analysis_results')
    par_analyzer.run_analysis()

if __name__ == "__main__":
    main()

