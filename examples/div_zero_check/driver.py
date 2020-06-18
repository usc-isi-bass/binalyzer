import argparse
import sys
import os

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.parallel_analyzer import ParallelAnalyzer

from div_zero_check_analysis import DivZeroAnalysis

def main():
    parser = argparse.ArgumentParser('Check for zero division errors')
    parser.add_argument('--root_dir', required=True, help='the root directory from where to search for all the elf files')
    parser.add_argument('--nthreads', default=1, type=int, help='number of processes to use.')

    args = parser.parse_args()
    root_dir = args.root_dir
    nthreads = args.nthreads
    
    analysis = DivZeroAnalysis()
    print("Parallel analysis:")
    par_analyzer = ParallelAnalyzer(analysis, root_dir=root_dir, nthreads=nthreads, results_path='./example_parallel_analysis_results')
    par_analyzer.run_analysis()

if __name__ == "__main__":
    main()

