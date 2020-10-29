import sys
import os
import angr

from binalyzer.analyzers.analysis import Analysis
from binalyzer.analyzers.analysis_results import AnalysisResults

# FROM: https://github.com/B-Con/crypto-algorithms/blob/master/md5.c
#md5_consts = {0xd76aa478, 0xf61e2562, 0x02441453, 0xa4beea44, 0xffeff47d}
md5_consts = {0xd76aa478, 0xf61e2562, 0xa4beea44, 0xffeff47d}

# FROM: https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c
sha256_consts = {0x6a09e667, 0xbb67ae85, 0xa54ff53a, 0x9b05688c, 0x5be0cd19}

class CryptoHashDetectionAnalysis(Analysis):

    def __init__(self, cached_results_path: str=None):
        super().__init__(cached_results_path)
      

    def results_constructor(self):
        return CryptoHashDetectionAnalysisResults

    def analyze(self, analysis_target, results):
        try:
            full_target_file_path = analysis_target.full_file_path
            target_file_name = analysis_target.file_name

            proj = angr.Project(full_target_file_path, auto_load_libs=False)
            cfg_fast = proj.analyses.CFGFast()

            for func_addr in cfg_fast.functions:
                func = cfg_fast.functions.function(addr=func_addr)
                if func is None:
                    results.add_err("Could not find function at addr 0x{:x}".format(func_addr))
                    continue

                discovered_md5_const_addrs = self.find_consts(func, md5_consts)
                discovered_md5_consts = {md5_const_addr[0] for md5_const_addr in discovered_md5_const_addrs}
                if len(discovered_md5_consts) == len(md5_consts):
                   discovered_md5 = DiscoveredMD5(func.name, func.addr, discovered_md5_const_addrs)
                   results.add_discovered_md5(discovered_md5)

                discovered_sha256_const_addrs = self.find_consts(func, sha256_consts)
                discovered_sha256_consts = {sha256_const_addr[0] for sha256_const_addr in discovered_sha256_const_addrs}
                if len(discovered_sha256_consts) == len(sha256_consts):
                   discovered_sha256 = DiscoveredMD5(func.name, func.addr, discovered_sha256_const_addrs)
                   results.add_discovered_sha256(discovered_sha256)

        except Exception as e:
            #raise e
            results.add_err(str(e))

    def find_consts(self, func, constants):
        const_addr_set = set()
        for block in func.blocks:
            insns = block.capstone.insns
            for insn in insns:
                for op in insn.operands:
                    if op.type == 2: # Capstone uses 2 for immediate operand types
                        if op.imm in constants:
                            const_addr_set.add((op.imm, insn.address))
        return const_addr_set

class CryptoHashDetectionAnalysisResults(AnalysisResults):

    def __init__(self):
        AnalysisResults.__init__(self)
        self.discovered_md5s = []
        self.discovered_sha256s = []
        self.errs = []

    def add_discovered_md5(self, discovered_md5):
        self.discovered_md5s.append(discovered_md5)

    def add_discovered_sha256(self, discovered_sha256):
        self.discovered_sha256s.append(discovered_sha256)

    def get_tracked_events(self):
        tracked_events = {}
        tracked_events['md5s'] = len(self.discovered_md5s)
        tracked_events['sha256'] = len(self.discovered_sha256s)
        tracked_events['errs'] = len(self.errs)
        tracked_events['timeouts'] = len([e for e in self.errs if 'timeout' in e])

        return tracked_events

    def copy_from_inner(self, other_analysis_results):
        for discovered_md5 in other_analysis_results.discovered_md5s:
            self.add_discovered_md5(discovered_md5)
        for discovered_sha256 in other_analysis_results.discovered_sha256s:
            self.add_discovered_sha256(discovered_sha256)
        for err in other_analysis_results.errs:
            self.add_err(err)

class DiscoveredCryptoHash:

    def __init__(self, crypto_hash_alg_name, func_name, func_addr, const_addr_set):
        self.crypto_hash_alg_name = crypto_hash_alg_name
        self.func_name = func_name
        self.func_addr = func_addr
        self.const_addr_set = const_addr_set

class DiscoveredMD5(DiscoveredCryptoHash):

    def __init__(self, func_name, func_addr, const_addr_set):
        super().__init__('MD5', func_name, func_addr, const_addr_set)

class DiscoveredSHA256(DiscoveredCryptoHash):

    def __init__(self, func_name, func_addr, const_addr_set):
        super().__init__('SHA256', func_name, func_addr, const_addr_set)

