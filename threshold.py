from neo4j import GraphDatabase, basic_auth
from construct_ckt import find_elbow
from pprint import pprint
from time import sleep
import os
from classifier import BT2_NAMES, BT3_NAMES, BT4_NAMES, BT5_NAMES, BT6_NAMES


BOLT = 'bolt://localhost:7687'
DRIVER = GraphDatabase.driver(BOLT, auth=basic_auth("neo4j", "ne04jcrus03"), encrypted=False)
# DRIVER = GraphDatabase.driver(BOLT, auth=basic_auth("neo4j", "Neo4jPas"), encrypted=False)

BT1_ADDRESSES = ['9.66.11.12', '9.66.11.13', '9.66.11.14', '10.1.2.22', '10.1.2.23', '10.1.2.24', '10.1.2.25',
                 '10.1.2.26', '10.1.2.28', '10.1.2.27', '10.1.2.29', '10.1.3.32', '10.1.3.33', '10.1.3.34',
                 '10.1.4.46', '10.1.4.47', '10.1.4.48', '10.1.4.49', '10.1.4.42', '10.1.4.43', '10.1.4.44',
                 '10.1.4.45']
GLOBAL_ADDRESSES = ['4.122.55.111', '4.122.55.112', '4.122.55.113', '4.122.55.114', '4.122.55.115', '4.122.55.117',
                    '4.122.55.2', '4.122.55.3', '4.122.55.4', '4.122.55.5', '4.122.55.6', '4.122.55.7', '4.122.55.21',
                    '4.122.55.22', '4.122.55.23', '4.122.55.24', '4.122.55.25', '4.122.55.26', '4.122.55.250']

# ANOTOVANY DATASET
RESULTS = {
    '9.66.11.12': 'critical',
    '9.66.11.13': 'critical',
    '9.66.11.14': 'critical',
    '10.1.2.22': 'critical',
    '10.1.2.23': 'critical',
    '10.1.2.24': 'critical',
    '10.1.2.25': 'critical',
    '10.1.2.26': 'critical',
    '10.1.2.28': 'critical',
    '10.1.2.27': 'critical',
    '10.1.2.29': 'critical',
    '10.1.4.46': 'critical',
    '10.1.4.47': 'critical',
    '10.1.4.48': 'critical',
    '10.1.4.49': 'critical',
    '10.1.3.32': 'noncritical',
    '10.1.3.33': 'noncritical',
    '10.1.3.34': 'noncritical',
    '10.1.4.42': 'noncritical',
    '10.1.4.43': 'noncritical',
    '10.1.4.44': 'noncritical',
    '10.1.4.45': 'noncritical',

    '4.122.55.2': 'critical',
    '4.122.55.3': 'critical',
    '4.122.55.4': 'critical',
    '4.122.55.5': 'noncritical',
    '4.122.55.6': 'noncritical',
    '4.122.55.7': 'critical',
    '4.122.55.250': 'critical',

    '4.122.55.111': 'noncritical',
    '4.122.55.112': 'noncritical',
    '4.122.55.113': 'noncritical',
    '4.122.55.114': 'noncritical',
    '4.122.55.115': 'noncritical',
    '4.122.55.116': 'noncritical',
    '4.122.55.117': 'noncritical',

    '4.122.55.21': 'noncritical',
    '4.122.55.22': 'noncritical',
    '4.122.55.23': 'noncritical',
    '4.122.55.24': 'noncritical',
    '4.122.55.25': 'noncritical',
    '4.122.55.26': 'noncritical'
}

# True positive - 9.66.11.13, 9.66.11.12, 9.66.11.14, 10.1.2.22, 10.1.2.23, 10.1.2.24, 10.1.2.25, 10.1.2.26, 10.1.2.27,
# 10.1.2.29, 10.1.4.46, 10.1.4.47, 10.1.4.49 = 13
# False positive - 10.1.4.42, 10.1.4.43, 10.1.4.44, 10.1.4.45 = 4
# True negative - 10.1.3.32, 10.1.3.33, 10.1.3.34 = 3
# False negative - 10.1.2.28, 10.1.4.48 = 2
# TPR = 13/15 - recall - 86.6%
# TNR = 3/7 - specificity - 42.86%
# PPV = TP / (TP + FP) = 13 / 17 - precision - 76.47%
# ACC = (TP + TN) / (P + N) = 16/22 = 72.73% accuracy

# postup
# extrahuj 5-minutove okna z DB
# nad nimi pust klasifikator
# nauc ho nad vsetkymi oknami a vysledkami, ako ma urcovat hranicu


# destination port
def categorize_addresses(accuracy=0.8):
    with(DRIVER.session()) as session:
        result = session.run("MATCH ()-[r:COMMUNICATES_WITH]->() "
                    "RETURN r.dst_port AS dst_port, COUNT(r.dst_port) AS port_count "
                    "ORDER BY port_count DESC")
        port_list = result.data()
        print(port_list[0:20])

    # TODO threshold nefunguje, zoberiem top ten
    x = 0
    if port_list:
        x, y, value = find_elbow(list(range(0, len(port_list))), [item['port_count'] for item in port_list])
        print("Elbow x:", x, ", y: ", y, ", value: ", value)
    # sleep(3600)

    critical_ip_addresses = {}
    set_of_ip_addresses = set()
    # for item in port_list[0:x+1]:
    for item in port_list[0:10]:
        destination_port = item['dst_port']
        print(destination_port)
        # pri datach z collectoru sa musia dat porty ako string
        with(DRIVER.session()) as session:
            # result = session.run("CALL gds.pageRank.stream({nodeQuery: 'MATCH (n) RETURN id(n) AS id', "
            #                      "relationshipQuery: 'MATCH (ip1:IP_ADDRESS)-[r:COMMUNICATES_WITH]->(ip2:IP_ADDRESS) "
            #                      "WHERE (ip1.address IN [\"9.66.11.12\", \"9.66.11.13\", \"9.66.11.14\", \"10.1.2.22\", \"10.1.2.23\", \"10.1.2.24\", \"10.1.2.25\", "
            #                      "\"10.1.2.26\", \"10.1.2.28\", \"10.1.2.27\", \"10.1.2.29\", \"10.1.3.32\", \"10.1.3.33\", \"10.1.3.34\", "
            #                      "\"10.1.4.46\", \"10.1.4.47\", \"10.1.4.48\", \"10.1.4.49\", \"10.1.4.42\", \"10.1.4.43\", \"10.1.4.44\", "
            #                      "\"10.1.4.45\"] OR ip2.address IN [\"9.66.11.12\", \"9.66.11.13\", \"9.66.11.14\", \"10.1.2.22\", \"10.1.2.23\", \"10.1.2.24\", \"10.1.2.25\", "
            #                      "\"10.1.2.26\", \"10.1.2.28\", \"10.1.2.27\", \"10.1.2.29\", \"10.1.3.32\", \"10.1.3.33\", \"10.1.3.34\", "
            #                      "\"10.1.4.46\", \"10.1.4.47\", \"10.1.4.48\", \"10.1.4.49\", \"10.1.4.42\", \"10.1.4.43\", \"10.1.4.44\", "
            #                      "\"10.1.4.45\"]) "
            #                      "RETURN DISTINCT id(ip1) AS source, id(ip2) AS target, r.dst_port AS dst_port'}) "
            #                      "YIELD nodeId, score RETURN gds.util.asNode(nodeId).address AS address, score "
            #                      "ORDER BY score DESC")
            result = session.run("CALL gds.pageRank.stream({nodeQuery: 'MATCH (n) RETURN id(n) AS id', "
                                 "relationshipQuery: 'MATCH (ip1:IP_ADDRESS)-[r:COMMUNICATES_WITH]->(ip2:IP_ADDRESS) "
                                 "WHERE (ip1.address IN [\"9.66.11.12\", \"9.66.11.13\", \"9.66.11.14\", \"10.1.2.22\", \"10.1.2.23\", \"10.1.2.24\", \"10.1.2.25\", "
                                 "\"10.1.2.26\", \"10.1.2.28\", \"10.1.2.27\", \"10.1.2.29\", \"10.1.3.32\", \"10.1.3.33\", \"10.1.3.34\", "
                                 "\"10.1.4.46\", \"10.1.4.47\", \"10.1.4.48\", \"10.1.4.49\", \"10.1.4.42\", \"10.1.4.43\", \"10.1.4.44\", "
                                 "\"10.1.4.45\"] OR ip2.address IN [\"9.66.11.12\", \"9.66.11.13\", \"9.66.11.14\", \"10.1.2.22\", \"10.1.2.23\", \"10.1.2.24\", \"10.1.2.25\", "
                                 "\"10.1.2.26\", \"10.1.2.28\", \"10.1.2.27\", \"10.1.2.29\", \"10.1.3.32\", \"10.1.3.33\", \"10.1.3.34\", "
                                 "\"10.1.4.46\", \"10.1.4.47\", \"10.1.4.48\", \"10.1.4.49\", \"10.1.4.42\", \"10.1.4.43\", \"10.1.4.44\", "
                                 "\"10.1.4.45\"]) "
                                 f"AND r.dst_port = {destination_port} "
                                 "RETURN DISTINCT id(ip1) AS source, id(ip2) AS target, r.dst_port AS dst_port'}) "
                                 "YIELD nodeId, score RETURN gds.util.asNode(nodeId).address AS address, score "
                                 "ORDER BY score DESC")
            # result = session.run("CALL gds.pageRank.stream({nodeQuery: 'MATCH (n) RETURN id(n) AS id', "
            #                      "relationshipQuery: 'MATCH (ip1:IP_ADDRESS)-[r:COMMUNICATES_WITH]->(ip2:IP_ADDRESS) "
            #                      "WHERE (ip1.address IN [\"4.122.55.111\", \"4.122.55.112\", \"4.122.55.113\", \"4.122.55.114\", \"4.122.55.115\", \"4.122.55.117\", "
            #                      "\"4.122.55.2\", \"4.122.55.3\", \"4.122.55.4\", \"4.122.55.5\", \"4.122.55.6\", \"4.122.55.7\", \"4.122.55.21\", "
            #                      "\"4.122.55.22\", \"4.122.55.23\", \"4.122.55.24\", \"4.122.55.25\", \"4.122.55.26\", \"4.122.55.250\"] OR ip2.address IN [\"4.122.55.111\", \"4.122.55.112\", \"4.122.55.113\", \"4.122.55.114\", \"4.122.55.115\", \"4.122.55.117\", "
            #                      "\"4.122.55.2\", \"4.122.55.3\", \"4.122.55.4\", \"4.122.55.5\", \"4.122.55.6\", \"4.122.55.7\", \"4.122.55.21\", "
            #                      "\"4.122.55.22\", \"4.122.55.23\", \"4.122.55.24\", \"4.122.55.25\", \"4.122.55.26\", \"4.122.55.250\"]) "
            #                      f"AND r.dst_port = {destination_port} "
            #                      "RETURN DISTINCT id(ip1) AS source, id(ip2) AS target, r.dst_port AS dst_port'}) "
            #                      "YIELD nodeId, score RETURN gds.util.asNode(nodeId).address AS address, score "
            #                      "ORDER BY score DESC")
            result_for_currrent_port = result.data()
        print("results for current port")
        print(result_for_currrent_port[0:20])
        # CyberCzech
        filtered_results = [list_item for list_item in result_for_currrent_port
                            if list_item['address'] in BT1_ADDRESSES]
                            # if list_item['address'] in GLOBAL_ADDRESSES]
                            # if list_item['address'] in list(BT2_NAMES.keys())]

        # print("filtered results")
        # print(filtered_results[0:10])
        # x, y, value = find_elbow(list(range(0, len(filtered_results))),
        #                          [list_item['score'] for list_item in filtered_results])
        # print("Elbow x:", x, ", y: ", y, ", value: ", value)

        # first naive attempt
        # zober hodnoty pageranku - pomer predchadzajucej a nasledujucej hodnoty
        # ip address, pagerank value,
        # chod od najvyssej hodnoty smerom nadol
        # pocitaj, akej precision at K sa dosiahne, aby bola vacsia ako
        # co najviac true positives a max 10% false negatives
        # uloz si hodnotu pagerank centrality

        counter = -1
        true_positives = 0
        true_negatives = 0
        last_allowed_centrality = 0
        for list_item in filtered_results:
            counter += 1

            print("processed IP", list_item['address'])
            if RESULTS[list_item['address']] == 'critical':
                true_positives += 1
                print("critical")
            else:
                true_negatives += 1
                print("noncritical")

            if true_negatives <= 0.1 * (true_positives + true_negatives):
                last_allowed_centrality = list_item['score']
                if destination_port in critical_ip_addresses:
                    critical_ip_addresses[destination_port].append(list_item['address'])
                else:
                    critical_ip_addresses[destination_port] = [list_item['address']]
            # else:
            #     print("last allowed centrality", list_item['score'])
            #     break
        print("last allowed centrality", last_allowed_centrality)
        print()
    print("end")


# Pouzil som citaciu od Sawilla, kt. navrhol AssetRank
# a v ramci clankov, kt. ho citovali som vyhladal PageRank

# https://dl.acm.org/doi/pdf/10.1145/1815396.1815508
# https://yahootechpulse.easychair.org/publications/download/ZBHj
# https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7828262
# https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.958.3955&rep=rep1&type=pdf
# https://scholar.google.com/scholar?hl=cs&as_sdt=0%2C5&q=Identifying+Critical+Attack+Assets+in+Dependency+Attack+Graphs&btnG=
