import abc
from abc import ABC
import os
import sys

from binalyzer.target_discovery.target_generator import TargetGenerator

ELF_HEADER = b"\x7fELF"

class ElfDiscoverer(TargetGenerator):

    def is_elf_file(self, full_file_name):
        with open(full_file_name, 'rb') as fd:
            header = fd.read(4)
            return header == ELF_HEADER

class ElfDiscovererSearch(ElfDiscoverer):

    def __init__(self, root_dir, remove_duplicates=True, break_limit=None):
        ElfDiscoverer.__init__(self, remove_duplicates=remove_duplicates, break_limit=break_limit)
        if not os.path.isdir(root_dir):
            raise Exception("Could not find root directory: {}".format(root_dir))
        self._root_dir = os.path.realpath(root_dir)


    def find_target_file(self):
        for r, d, f in os.walk(self._root_dir):
            for file_name in f:
                full_file_path = os.path.abspath(os.path.join(r, file_name))
                # We don't want to analyze anything that may be somewhere else
                if not os.path.islink(full_file_path):
                    if self.is_elf_file(full_file_path):
                        yield full_file_path

class ElfDiscovererList(ElfDiscoverer):

    def __init__(self, elf_list, remove_duplicates=True, break_limit=None):
        ElfDiscoverer.__init__(self, remove_duplicates=remove_duplicates, break_limit=break_limit)
        self._elf_list = elf_list

    def find_target_file(self):
        for i, elf_file_path in enumerate(self._elf_list):
            if os.path.isfile(elf_file_path):
                if self.is_elf_file(elf_file_path):
                    elf_file_path = os.path.abspath(elf_file_path)
                    yield elf_file_path
                else:
                    print("Err in elf list: {} exists, but is not an elf file".format(elf_file_path), file=sys.stderr)
            else:
                print("Err in elf list: could not find file: {} (please use absolute paths)".format(elf_file_path), file=sys.stderr)

class ElfDiscovererListFile(ElfDiscoverer):

    def __init__(self, elf_list_file, remove_duplicates=True, break_limit=None):
        ElfDiscoverer.__init__(self, remove_duplicates=remove_duplicates, break_limit=break_limit)
        self._elf_list_file = elf_list_file

    def find_target_file(self):
        with open(self._elf_list_file, 'r') as fd:
            for i, line in enumerate(fd):
                line = line.strip()
                if len(line) <= 0:
                    continue
                if line[0] == '#': # Allows us to put comments in elf list file
                    continue
                elf_file_path = line
                if os.path.isfile(elf_file_path):
                    if self.is_elf_file(elf_file_path):
                        elf_file_path = os.path.abspath(elf_file_path)
                        yield elf_file_path
                    else:
                        #raise Exception("Err in elf list file on line {}: file {} exists, but is not an elf file".format(i, elf_file_path))
                        print("Err in elf list file on line {}: file {} exists, but is not an elf file".format(i, elf_file_path), file=sys.stderr)
                else:
                    #raise Exception("Err in elf list file on line {}: could not find file: {} (please use absolute paths)".format(i, elf_file_path))
                    print("Err in elf list file on line {}: could not find file: {} (please use absolute paths)".format(i, elf_file_path), file=sys.stderr)

