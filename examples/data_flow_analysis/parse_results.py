import argparse
import jsonpickle
import numpy as np
import matplotlib.pyplot as plt

inf = float('inf')
ninf = -inf

def main():
    parser = argparse.ArgumentParser(description="Parse the results counting the number of memory access operations.")
    parser.add_argument('file', help='The file containing the results to parse')
    args = parser.parse_args()
    results_file_name = args.file
    all_results, deserialization_errs = read_results(results_file_name)
    num_results = len(all_results)
    print("Num deserialization errs: {}".format(deserialization_errs))
    print("Total results: {}".format(num_results))

    num_timeouts = 0
    num_oom_errors = 0
    successes = []
    for results in all_results:
        analysis_target = results.analysis_target
        analysis_results = results.analysis_results
        target_file = analysis_target.full_file_path
        file_name = analysis_target.file_name

        errs = analysis_results.errs

        if len(errs) > 0:
            if any('timeout' in err.lower() for err in errs):
                num_timeouts += 1
            elif any('killed by signal: 9' in err.lower() for err in errs):
                num_oom_errors += 1
            else:
                print("Other error: {}".format(errs))
        else:
            successes.append(results)

    print("Num timeouts: {}".format(num_timeouts))
    print("Num out of memory errs: {}".format(num_oom_errors))
    for results in successes:
        analysis_target = results.analysis_target
        analysis_results = results.analysis_results
        target_file = analysis_target.full_file_path
        file_name = analysis_target.file_name
        num_edges = analysis_results.get_num_edges()
        num_nodes = analysis_results.get_num_nodes()
        print("Success: {}".format(file_name))
        print("  Nodes: {}".format(num_nodes))
        print("  Edges: {}".format(num_edges))

def read_results(results_file_name):
    results_list = []
    deserialization_errs = 0
    with open(results_file_name, 'r') as fd:
        for i, line in enumerate(fd):
            try:
                results = jsonpickle.decode(line)
                results_list.append(results)
            except Exception as e:
                deserialization_errs += 1
    return results_list, deserialization_errs

if __name__ == "__main__":
    main()

