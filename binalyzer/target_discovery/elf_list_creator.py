import argparse

from binalyzer.target_discovery.elf_discoverer import ElfDiscovererSearch

def main():
    parser = argparse.ArgumentParser('Search for ELF files and return their paths.')
    parser.add_argument('--root_dir', required=True, help='The root directory to search from.')
    parser.add_argument('--break_limit', required=False, help='An upper bound for the number of ELF files to search for.', default=-1)

    args = parser.parse_args()
    root_dir = args.root_dir
    break_limit = args.break_limit

    eds = ElfDiscovererSearch(root_dir, break_limit)
    for full_file_path in eds.find_target_file():
        print(full_file_path)

if __name__ == "__main__":
    main()
