import argparse
import os


class AnalyzerArgumentParser(argparse.ArgumentParser):
    '''
    An argument parser for receiving the parameters of an Analyzer object as command line arguments.
    '''

    def __init__(self, *args, **kwargs):
        argparse.ArgumentParser.__init__(self, *args, add_help=False, **kwargs)
        binalyzer_arg_group = self.add_argument_group(title='Binalyzer Arguments', description='The arguments for the binalyzer driver')
        binalyzer_arg_group.add_argument('--root_dir', help='The root directory from where the search for analysis targets will start. (mutually exclusive with elf_list)')
        binalyzer_arg_group.add_argument('--elf_list', help='A list of strings specifying the file names of the analysis targets. (mutually exclusive with root_dir)')
        binalyzer_arg_group.add_argument('--break_limit', help='An upper bound on the number of AnalysisTargets to generate', type=int)
        binalyzer_arg_group.add_argument('--remove_duplicates', help='Ensure all AnalysisTargets have a unique MD5 hash', type=bool, default=True)
        binalyzer_arg_group.add_argument('--results_path', help='Either a directory or a filename. If a directory, the analysis results will be stored in a file in this directory (the file name will be the time the analysis started). If a filename, the analysis results will be stored in this file. The default is the current working directory.', default=os.getcwd())
        binalyzer_arg_group.add_argument('--timeout', help='The number of seconds after which the analysis of a single AnalysisTarget will be stopped.', type=int, default=None)

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
        parallel_arg_group = self.add_argument_group(title='Parallel Binalyzer Arguments', description='The arguments for the parallel binalyzer driver')
        parallel_arg_group.add_argument('--nthreads', required=False, default=1, type=int, help='The number of processes to use.')

