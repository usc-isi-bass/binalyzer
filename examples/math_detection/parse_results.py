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

    for results in all_results:
        analysis_target = results.analysis_target
        analysis_results = results.analysis_results
        target_file = analysis_target.full_file_path
        file_name = analysis_target.file_name
        func_addr_to_features = analysis_results.func_addr_to_features

        for (func_name, func_addr), features in func_addr_to_features.items():
            print(features)



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
