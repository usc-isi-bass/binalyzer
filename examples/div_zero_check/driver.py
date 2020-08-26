import argparse
import sys
import os

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.parallel_analyzer import ParallelAnalyzer
from binalyzer.util.analyzer_argument_parser import ParallelAnalyzerArgumentParser

from div_zero_check_analysis import DivZeroAnalysis

def main():
    analyzer_argument_parser = ParallelAnalyzerArgumentParser()

    parser = argparse.ArgumentParser('Check for zero division errors', parents=[analyzer_argument_parser])

    args = parser.parse_args()
    root_dir = args.root_dir
    elf_list_file = args.elf_list_file
    nthreads = args.nthreads
    
    analysis = DivZeroAnalysis()
    par_analyzer = ParallelAnalyzer(analysis, root_dir=root_dir, elf_list_file=elf_list_file, nthreads=nthreads, results_path='./example_parallel_analysis_results')
    par_analyzer.run_analysis()

if __name__ == "__main__":
    main()

