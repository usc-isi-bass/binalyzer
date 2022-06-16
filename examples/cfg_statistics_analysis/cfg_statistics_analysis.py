import sys
import os
import logging
import re


logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('pyvex').disabled = True
logging.getLogger('pyvex').propagate = False
logging.getLogger('claripy').disabled = True
logging.getLogger('claripy').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

import angr
import pyvex

# Because apparently python only adds the parent directory of the running script to the PATH.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

inf = float('inf')
ninf = -inf

class CfgStatisticsAnalysis(Analysis):

    def results_constructor(self):
        return CfgStatisticsAnalysisResults

    def analyze(self, analysis_target, analysis_results):
        try:
            full_target_file_path = analysis_target.full_file_path
            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)
            cfg_num_nodes = len(cfg.graph.nodes())
            analysis_results.set_cfg_num_nodes(cfg_num_nodes)
            cfg_num_edges = len(cfg.graph.edges())
            analysis_results.set_cfg_num_edges(cfg_num_edges)
            
            cfg_max_node_byte_size = ninf
            cfg_min_node_byte_size = inf
            tot_node_size = 0
            for node in cfg.nodes_iter():
                node_size = node.size

                tot_node_size += node_size

                cfg_min_node_byte_size = min(node_size, cfg_min_node_byte_size)
                cfg_max_node_byte_size = max(node_size, cfg_max_node_byte_size)
            ave_node_size = tot_node_size / cfg_num_nodes
            analysis_results.set_cfg_min_node_byte_size(cfg_min_node_byte_size)
            analysis_results.set_cfg_max_node_byte_size(cfg_max_node_byte_size)
            analysis_results.set_cfg_ave_node_byte_size(ave_node_size)


        except Exception as e:
            analysis_results.add_err(str(e))


class CfgStatisticsAnalysisResults(AnalysisResults):
    def __init__(self):
        AnalysisResults.__init__(self)
        self.cfg_num_nodes = None
        self.cfg_num_edges = None
        self.cfg_min_node_byte_size = None
        self.cfg_max_node_byte_size = None
        self.cfg_ave_node_byte_size = None
        self.errs = []

    def set_cfg_num_nodes(self, cfg_num_nodes):
        self.cfg_num_nodes = cfg_num_nodes

    def get_cfg_num_nodes(self):
        return self.cfg_num_nodes
    
    def set_cfg_num_edges(self, cfg_num_edges):
        self.cfg_num_edges = cfg_num_edges

    def get_cfg_num_edges(self):
        return self.cfg_num_edges

    def set_cfg_min_node_byte_size(self, cfg_min_node_byte_size):
        self.cfg_min_node_byte_size = cfg_min_node_byte_size

    def get_cfg_min_node_byte_size(self):
        return self.cfg_min_node_byte_size

    def set_cfg_max_node_byte_size(self, cfg_max_node_byte_size):
        self.cfg_max_node_byte_size = cfg_max_node_byte_size

    def get_cfg_max_node_byte_size(self):
        return self.cfg_max_node_byte_size

    def set_cfg_ave_node_byte_size(self, cfg_ave_node_byte_size):
        self.cfg_ave_node_byte_size = cfg_ave_node_byte_size

    def get_cfg_ave_node_byte_size(self):
        return self.cfg_ave_node_byte_size


    def add_err(self, err):
        self.errs.append(err)

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['errs'] = len(self.errs)

        return tracked_events

    def copy_from_inner(self, other_analysis_results):
        self.set_cfg_num_nodes(other_analysis_results.cfg_num_nodes)
        self.set_cfg_num_edges(other_analysis_results.cfg_num_edges)
        self.set_cfg_min_node_byte_size(other_analysis_results.cfg_min_node_byte_size)
        self.set_cfg_max_node_byte_size(other_analysis_results.cfg_max_node_byte_size)
        self.set_cfg_ave_node_byte_size(other_analysis_results.cfg_ave_node_byte_size)
        for err in other_analysis_results.errs:
            self.add_err(err)


