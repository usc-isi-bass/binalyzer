import argparse
import os


class AnalyzerArgumentParser(argparse.ArgumentParser):
    '''
    An argument parser for receiving the parameters of an Analyzer object as command line arguments.
    '''

    def __init__(self, *args, **kwargs):
        argparse.ArgumentParser.__init__(self, *args, add_help=False, **kwargs)
        self.add_argument('--root_dir', help='The root directory from where the search for analysis targets will start. (mutually exclusive with elf_list)')
        self.add_argument('--elf_list', help='A list of strings specifying the file names of the analysis targets. (mutually exclusive with root_dir)')
        self.add_argument('--break_limit', help='An upper bound on the number of AnalysisTargets to generate', type=int)
        self.add_argument('--remove_duplicates', help='Ensure all AnalysisTargets have a unique MD5 hash', type=bool, default=True)
        self.add_argument('--results_path', help='Either a directory or a filename. If a directory, the analysis results will be stored in a file in this directory (the file name will be the time the analysis started). If a filename, the analysis results will be stored in this file. The default is the current working directory.', default=os.getcwd())
        self.add_argument('--timeout', help='The number of seconds after which the analysis of a single AnalysisTarget will be stopped.', type=int, default=None)

class SequentialAnalyzerArgumentParser(AnalyzerArgumentParser):
    '''
    An argument parser for receiving the parameters of an SequentialAnalyzer object as command line arguments.
    '''
    def __init__(self, *args, **kwargs):
        AnalyzerArgumentParser.__init__(self, *args, **kwargs)

class ParallelAnalyzerArgumentParser(AnalyzerArgumentParser):
    '''
    An argument parser for receiving the parameters of an ParallelAnalyzer object as command line arguments.
    '''
    def __init__(self, *args, **kwargs):
        AnalyzerArgumentParser.__init__(self, *args, **kwargs)
        self.add_argument('--nthreads', required=False, default=1, type=int, help='The number of processes to use.')

