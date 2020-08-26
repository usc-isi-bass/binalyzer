import sys
import os
import argparse
import json
import pygments
from pygments.lexers import JsonLexer
from pygments.formatters import Terminal256Formatter

def main():
    parser = argparse.ArgumentParser(description='A tool to visualize the AnalysisResults objects created by binalyzer.')
    parser.add_argument('--results_file', required=False, help='the file containing the results. We\'ll use stdin if not provided.')

    args = parser.parse_args()

    results_file = args.results_file

    try:
        fd = None
        if results_file is None:
            fd = sys.stdin
        else:
            fd = open(results_file, 'r')

        for line in fd:
            line = line.strip()
            results = json.loads(line)
            json_pp = json.dumps(results, indent=4)
            print(pygments.highlight(json_pp, JsonLexer(), Terminal256Formatter()))
            print("=" * 128)

    finally:
        if fd is not None and fd is not sys.stdin:
            fd.close()
        




if __name__ == "__main__":
    main()
