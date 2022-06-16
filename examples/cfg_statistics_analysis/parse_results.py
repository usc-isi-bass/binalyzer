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

    cfg_min_num_nodes = inf
    cfg_max_num_nodes = ninf
    cfg_tot_num_nodes = 0
    cfg_tot_num_edges = 0

    cfg_tot_node_byte_size = 0

    for results in all_results:
        analysis_target = results.analysis_target
        analysis_results = results.analysis_results
        target_file = analysis_target.full_file_path
        file_size = analysis_target.file_size
        file_name = analysis_target.file_name

       
        cfg_num_nodes = analysis_results.cfg_num_nodes
        cfg_tot_num_nodes += cfg_num_nodes

        cfg_num_edges = analysis_results.cfg_num_edges
        cfg_tot_num_edges += cfg_num_edges

        cfg_ave_node_byte_size = analysis_results.cfg_ave_node_byte_size
        cfg_tot_node_byte_size += cfg_ave_node_byte_size

        


    print("Average num nodes: {}".format(cfg_tot_num_nodes / num_results))
    print("Average num edges: {}".format(cfg_tot_num_edges / num_results))
    print("Average average node byte size : {}".format(cfg_tot_node_byte_size / num_results))

        



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
