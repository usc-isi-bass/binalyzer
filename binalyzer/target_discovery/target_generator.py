import abc
from abc import ABC
import os
import ntpath
import hashlib

from binalyzer.target_discovery.analysis_target import AnalysisTarget

class TargetGenerator(ABC):

    '''
    remove_duplicates: whether to remove files with the same MD5 hash
    break_limit: An upper bound on the number of targets to return. 'None' indicates no upper bound
    '''
    @abc.abstractmethod
    def __init__(self, remove_duplicates=True, break_limit=None):
        self._remove_duplicates = remove_duplicates
        self._break_limit = break_limit
        self._cache = {}

    def find_targets(self):
        break_counter = 0
        for full_target_file_path in self.find_target_file():
            if self._break_limit is not None and break_counter >= self._break_limit:
                break
            target_file_md5 = self.md5_file(full_target_file_path)
            if target_file_md5 not in self._cache:
                
                target_file_name = ntpath.basename(full_target_file_path)
                target_file_size = os.stat(full_target_file_path).st_size

                target = AnalysisTarget(full_target_file_path, target_file_name, target_file_size, target_file_md5)
                self._cache[target_file_md5] = target
                break_counter += 1
                yield target
            elif not self._remove_duplicates:
                target = self._cache[target_file_md5]
                break_counter += 1
                yield target

    @abc.abstractmethod
    def find_target_file(self):
        pass

    def md5_file(self, file_name):
        # I got this from: https://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file
        hash_md5 = hashlib.md5()
        with open(file_name, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

        
