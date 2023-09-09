import argparse

from binalyzer.target_discovery.elf_discoverer import ElfDiscovererSearch

def main():
    parser = argparse.ArgumentParser('Search for ELF files and return their paths.')
    parser.add_argument('--root-dir', required=True, help='The root directory to search from.')
    parser.add_argument('--remove-duplicates', dest='remove_duplicates', action='store_true', default=True, help='Removes duplicate ELFs (up to their MD5 hash).')
    parser.add_argument('--no-remove-duplicates', dest='remove_duplicates', action='store_false', help='Do not remove duplicate ELFs (up to their MD5 hash).')
    parser.add_argument('--break-limit', required=False, type=int, help='An upper bound for the number of ELF files to search for.', default=None)

    args = parser.parse_args()
    root_dir = args.root_dir
    remove_duplicates = args.remove_duplicates
    break_limit = args.break_limit

    eds = ElfDiscovererSearch(root_dir, remove_duplicates, break_limit)
    for analysis_target in eds.find_targets():
        print(analysis_target.full_file_path)

if __name__ == "__main__":
    main()
