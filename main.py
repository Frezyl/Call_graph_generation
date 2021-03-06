import pdb
import angr
import networkx
import logging
from tqdm import tqdm


def cfg_node_tagging(_fast: angr.analyses.cfg.cfg_fast.CFGFast, _tag_dict):
    """
    Extends the given dictionary with given angr fast project nodes

    :param _fast: angr fast project
    :param _tag_dict: dictionary of bytes to CFG node
    :return: extended dictionary of bytes to CFG node
    """
    for _node in _fast.model.nodes():
        node_bytes = _node.byte_string
        if node_bytes not in _tag_dict:
            _tag_dict[node_bytes] = len(_tag_dict) + 1
    return _tag_dict


def get_current_node_tag(addr, _tag_dict):
    """
    Returns the tag of CFG node based on memory address

    :param addr: address of call graph node
    :param _tag_dict: dictionary of bytes to CFG node
    :return: tag of CFG node
    """
    cfg_node = fast.model.get_any_node(addr)
    return _tag_dict[cfg_node.byte_string]


def count_all_neighbors(_node):
    """
    Returns neighbour count of given node

    :param _node: which node's neighbour count requested
    :return: number of neighbours
    """
    neighbor_count = len(list(networkx.all_neighbors(fast_call_graph, _node)))
    return neighbor_count


def write_neighbors_with_indices(_fast_call_graph, node_idx_dict: dict, node):
    """
    Write a node's neighbours into file based on their indices

    :param _fast_call_graph: the node's graph
    :param node_idx_dict: node to index dictionary
    :param node: which node's neighbours should be written
    """
    neighbor_list = networkx.all_neighbors(_fast_call_graph, node)
    for neighbor in neighbor_list:
        idx = node_idx_dict[neighbor]
        results.write(f" {idx}")
    results.write(f"\n")
    return


def node_index_generation(_fast_call_graph, _node_idx_dict, _idx_node_dict):
    """
    Generate node indices and store them in 2 dictionary (dictionary both ways)

    :param _fast_call_graph: target graph
    :param _node_idx_dict: node to index dict
    :param _idx_node_dict: index to node dict
    :return: _node_idx_dict, _idx_node_dict
    """
    _node_idx = 0
    nodes_list = list(_fast_call_graph.nodes())
    for _node in nodes_list:
        _node_idx_dict[_node] = _node_idx
        _idx_node_dict[_node_idx] = _node
        _node_idx += 1
    return _node_idx_dict, _idx_node_dict


if __name__ == '__main__':
    logging.getLogger('angr').setLevel('CRITICAL')  # TODO set logger level to sensible value

    ubi_samples = []
    """list of ubiquiti file names"""

    with open(f"ubi_libraries.txt", "rt") as f_list:  # load ubiquiti file names with collected libraries
        for line in f_list:
            ubi_samples.append(line.split()[0])

    ubi_ARM = []
    """list of ubiquiti ARM file names"""

    with open(f"ubi_ARM.txt", "rt") as ubi_ARM_f:
        for line in ubi_ARM_f:
            ubi_ARM.append(line.split()[0])

    ubi_samples = [sample for sample in ubi_samples if sample in ubi_ARM]  # filter for ARM samples

    dlink_samples = []
    """list of dlink file names"""

    with open(f"dlink_libraries.txt", "rt") as f_list:  # load dlink file names with collected libraries
        for line in f_list:
            dlink_samples.append(line.split()[0])

    dlink_ARM = []
    """list of dlink ARM file names"""

    with open(f"dlink_ARM.txt", "rt") as dlink_ARM_f:
        for line in dlink_ARM_f:
            dlink_ARM.append(line.split()[0])

    dlink_samples = [sample for sample in dlink_samples if sample in dlink_ARM]  # filter for ARM samples

    tag_dict = dict()
    """tag dictionary for nodes"""

    malware_samples = list()

    with open(f"malware.txt", "rt") as malware_samples_f:  # load malware sample names
        for line in malware_samples_f:
            malware_samples.append(line.split()[0])

    print(f"{len(ubi_samples)} ubiquiti samples loaded")
    print(f"{len(dlink_samples)} dlink samples loaded")
    print(f"{len(malware_samples)} malware samples loaded")

    with open(f"call_graphs.txt", "wt") as results:

        # number of graphs
        N = len(ubi_samples) + len(dlink_samples) + len(malware_samples)
        results.write(f"{N}\n")

        feat_dict = {}
        """dictionary for node feature tags"""

        path_to_libraries = f"../libraries/"
        """path to dynamically linked libraries"""

        samples = list()
        """list of all samples"""

        samples = ubi_samples + dlink_samples + malware_samples  # combine all sample names into 1 list

        print(f"{len(dlink_samples) + len(ubi_samples)} benign samples loaded")
        print(f"{len(malware_samples)} malware samples loaded")

        exception_samples = list()
        """collect samples where exceptions occurred"""

        samples = tqdm(samples)
        for sample in samples:
            samples.set_description("Processing samples")
            try:

                if sample in ubi_samples:
                    fast_proj: angr.project.Project = angr.Project('../ubiquiti/' + sample,
                                                                   load_options={
                                                                       'auto_load_libs': True,
                                                                       'except_missing_libs': True,
                                                                       'ld_path': [f'{path_to_libraries}{sample}']
                                                                   },
                                                                   use_sim_procedures=False)
                    """angr project"""

                elif sample in dlink_samples:

                    fast_proj: angr.project.Project = angr.Project('../dlink/' + sample,
                                                                   load_options={
                                                                       'auto_load_libs': True,
                                                                       'except_missing_libs': True,
                                                                       'ld_path': [f'{path_to_libraries}{sample}']
                                                                   },
                                                                   use_sim_procedures=False)
                    """angr project"""
                elif sample in malware_samples:
                    fast_proj: angr.project.Project = angr.Project('../malware/' + sample, load_options={'auto_load_libs': False})

                fast: angr.analyses.cfg.cfg_fast.CFGFast = fast_proj.analyses.CFGFast()
                """CFGFast analysis"""

                fast_cfg: networkx.classes.digraph.DiGraph = fast.graph
                """CFGFast graph"""

                fast_call_graph: networkx.DiGraph = fast.functions.callgraph
                """call graph of CFGFast analysis"""

                fast_call_graph: networkx.Graph = fast_call_graph.to_undirected()
                """change call graph to undirected"""

                graph_label = None
                """graph label for NN
                
                0 malware
                
                1 benign
                """

                if sample in malware_samples:
                    graph_label = 0  # set graph label to 0 for malware
                elif sample in dlink_samples or ubi_samples:
                    graph_label = 1  # set graph label to 1 for benign

                tag_dict = cfg_node_tagging(fast, tag_dict)
                """extend node tag dictionary with new graph"""

                # write number of nodes
                n = networkx.number_of_nodes(fast_call_graph)
                results.write(f"{n} {graph_label}\n")

                node_idx_dict = dict()
                """node to index dictionary"""

                idx_node_dict = dict()
                """index to node dictionary"""

                # create node indices
                node_idx_dict, idx_node_dict = node_index_generation(fast_call_graph, _node_idx_dict=node_idx_dict, _idx_node_dict=idx_node_dict)

                for index in idx_node_dict:  # iterate over node indices
                    node = idx_node_dict[index]  # get node from index
                    node_idx = node_idx_dict[node]
                    memory_address = node  # get memory address of node
                    node_tag = get_current_node_tag(addr=memory_address, _tag_dict=tag_dict)  # get node tag

                    number_of_neighbors = count_all_neighbors(_node=idx_node_dict[index])  # get number of neighbours
                    results.write(f"{node_tag} {number_of_neighbors}")  # write number of neighbours to file
                    write_neighbors_with_indices(fast_call_graph, node_idx_dict, idx_node_dict[node_idx])  # write neighbour indices to file

            except Exception as e:  # catch exception
                print(e)
                exception_samples.append(sample + "\n")  # append file name to exception list

    print(f"{len(exception_samples)} exceptions occured")
    with open("exceptions.txt", "wt") as exception_samples_f:
        exception_samples_f.writelines(exception_samples)
