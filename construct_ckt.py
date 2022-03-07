# Algoritmus
# 1. vezmi IP adresy, kt. boli oznacene ako dolezite
# 2. zisti ich IP adresy
# 3. pozri logy
import json
from pprint import pprint
from neo4j import GraphDatabase, basic_auth
from pprint import pprint
from math import sqrt

# TODO zoznam veci, kt. je potreba vyriesit
#  1.) link prediction vs. existing links
#  2.) timestamps
#  3.) orientation of edges
#  4.) optimization criteria
#  5.) method that determines dependencies for specific devices
#  6.) new data, communication within subnets


BOLT = 'bolt://localhost:7687'
DRIVER = GraphDatabase.driver(BOLT, auth=basic_auth("neo4j", "ne04jcrus03"), encrypted=False)
# DRIVER = GraphDatabase.driver(BOLT, auth=basic_auth("neo4j", "Neo4jPas"), encrypted=False)


def obtain_pairs_of_ip_addresses(ip_flow_filename, syslog_filename, ip_addresses=None):
    """
    Outputs pairs of IP addresses in IP flows.
    :param ip_addresses: list of ip addresses, for which we will obtain communication pairs
    :type ip_addresses:
    :return:
    :rtype:
    """
    # dictionary contains src_ip as key and its dst_ips, start and end timestamps
    ip_flow_dictionary = {}
    with open(ip_flow_filename, 'r') as jsonfile:
        for line in jsonfile.readlines():
            data = json.loads(line)
            if (data["sourceIPv4Address"], data["destinationIPv4Address"]) in ip_flow_dictionary:
                ip_flow_dictionary[(data["sourceIPv4Address"], data["destinationIPv4Address"])]\
                    .append((data["biFlowStartMilliseconds"], data["biFlowEndMilliseconds"], []))
            else:
                ip_flow_dictionary[(data["sourceIPv4Address"], data["destinationIPv4Address"])] = \
                    [(data["biFlowStartMilliseconds"], data["biFlowEndMilliseconds"], [])]

    # struktura slovnika
    # src_ip, dst_ip, list
    # item listu ma strukturu: [(flow_start, flow_end), list of events]
    # event ma tvar (timestamp, message)
    # pprint(ip_flow_dictionary)

    counter = 0
    with open(syslog_filename, 'r') as syslog_file:
        # mam jeden event s casovou znamkou a IP adresou
        for line in syslog_file.readlines():
            data = json.loads(line)
            timestamp = data["timestamp"]
            message = data["message"]
            fromhost_ip = data["fromhost_ip"]

            if fromhost_ip in ip_flow_dictionary:
                for (src_ip_key, dst_ip_key) in ip_flow_dictionary:
                    if fromhost_ip == src_ip_key or fromhost_ip == dst_ip_key:
                        for (start, end, event_list) in ip_flow_dictionary[src_ip_key][dst_ip_key]:
                            if start <= timestamp <= end:
                                event_list.append((timestamp, message))
                                counter += 1
                                if counter == 100:
                                    with open('data/data_output.json') as output_file:
                                        json.dump(ip_flow_dictionary, output_file)
                                        # pprint(ip_flow_dictionary)
                                    print("printed")
                                    return None
                                # TODO toto bude príliš pomalé
                                # pass
    # pprint(ip_flow_dictionary)


# určiť páry adries, kt. komunikovali
# zobrat jeden par a pozriet logy


def get_ips_that_communicated(ip_flow_filename='data/data_ipflow.json'):
    ip_flow_dictionary = {}
    with open(ip_flow_filename, 'r') as jsonfile:
        for line in jsonfile.readlines():
            data = json.loads(line)
            if (data["sourceIPv4Address"], data["destinationIPv4Address"]) in ip_flow_dictionary:
                ip_flow_dictionary[(data["sourceIPv4Address"], data["destinationIPv4Address"])] \
                    .append((data["biFlowStartMilliseconds"], data["biFlowEndMilliseconds"], []))
            else:
                ip_flow_dictionary[(data["sourceIPv4Address"], data["destinationIPv4Address"])] = \
                    [(data["biFlowStartMilliseconds"], data["biFlowEndMilliseconds"], [])]
    # ip_pairs = ip_flow_dictionary.keys()
    # with open('data/data_output.json', 'w') as output_file:
    #     json.dump(ip_pairs, output_file)
    # pprint(ip_flow_dictionary.keys())
    return ip_flow_dictionary


def create_ips_in_db(time_treshold=1552989909721, ip_flow_filename='data/data_ipflow.json'):
    ip_flow_dict = get_ips_that_communicated(ip_flow_filename)
    for (src_ip, dst_ip) in ip_flow_dict:
        if (src_ip.startswith('9.') or src_ip.startswith('10.') or src_ip.startswith('4.')) and \
                (dst_ip.startswith('9.') or dst_ip.startswith('10.') or dst_ip.startswith('4.')):
            for (start, end, event_list) in ip_flow_dict[(src_ip, dst_ip)]:
                if end <= time_treshold:
                    create_connections_in_database(src_ip, dst_ip, start, end)


# '4.122.55.5', '9.66.66.12'
def get_timestamps_for_ip_pair(src_ip, dst_ip, ip_flow_filename='data/data_ipflow.json'):
    timestamps = []
    with open(ip_flow_filename, 'r') as jsonfile:
        for line in jsonfile.readlines():
            data = json.loads(line)
            if data["sourceIPv4Address"] == src_ip and data["destinationIPv4Address"] == dst_ip:
                timestamps.append((data["biFlowStartMilliseconds"], data["biFlowEndMilliseconds"]))
    return timestamps


def get_logs_for_ip_pair(src_ip, dst_ip, ip_flow_filename='data/data_ipflow.json',
                         syslog_filename='data/data_syslog.json'):
    timestamps = get_timestamps_for_ip_pair(src_ip, dst_ip, ip_flow_filename)
    log_events = []
    with open(syslog_filename, 'r') as jsonfile:
        for line in jsonfile.readlines():
            data = json.loads(line)
            if data["fromhost_ip"] == src_ip or data["fromhost_ip"] == dst_ip:
                for (start, end) in timestamps:
                    if start <= data["timestamp"] <= end:
                        log_events.append((data["message"], data["timestamp"]))
    pprint(log_events)


# Ako urcit, co je DNS server, DC server
def get_set_of_ips_syslog(filename='data/data_syslog.json'):
    set_of_ips = set()
    with open(filename, 'r') as syslog_file:
        for line in syslog_file.readlines():
            data = json.loads(line)
            set_of_ips.add(data["fromhost_ip"])
    pprint(set_of_ips)


def get_set_of_ips_winlog(filename='data/data_winlog.json'):
    set_of_ips = set()
    with open(filename, 'r') as winlog_file:
        for line in winlog_file.readlines():
            data = json.loads(line)
            set_of_ips.add(data["host_ip"])
    pprint(set_of_ips)


def get_set_of_ips_flow(filename='data/data_ipflow.json'):
    set_of_ips = set()
    with open(filename, 'r') as ip_flow_file:
        for line in ip_flow_file.readlines():
            data = json.loads(line)
            set_of_ips.add(data["sourceIPv4Address"])
            set_of_ips.add(data["destinationIPv4Address"])
    pprint(set_of_ips)

# MERGE r=(:IP_ADDRESS {address: '147.251.12.15'})-[:COMMUNICATES_WITH {timestamp:15}]->
# (:IP_ADDRESS {address: '147.251.12.16'})


# IP adresy z winlogu
# {'10.7.100.117',
#  '10.7.101.14',
#  '10.7.101.22',
#  '10.7.101.23',
#  '10.7.101.24',
#  '10.7.101.32',
#  '10.7.101.33',
#  '10.7.101.42',
#  '10.7.101.43',
#  '10.7.101.46',
#  '10.7.101.47',
#  '10.7.102.14',
#  '10.7.102.22',
#  '10.7.102.23',
#  '10.7.102.24',
#  '10.7.102.32',
#  '10.7.102.33',
#  '10.7.102.42',
#  '10.7.102.43',
#  '10.7.102.46',
#  '10.7.102.47',
#  '10.7.103.14',
#  '10.7.103.22',
#  '10.7.103.23',
#  '10.7.103.24',
#  '10.7.103.32',
#  '10.7.103.33',
#  '10.7.103.42',
#  '10.7.103.43',
#  '10.7.103.46',
#  '10.7.103.47',
#  '10.7.104.14',
#  '10.7.104.22',
#  '10.7.104.23',
#  '10.7.104.24',
#  '10.7.104.32',
#  '10.7.104.33',
#  '10.7.104.42',
#  '10.7.104.43',
#  '10.7.104.46',
#  '10.7.104.47',
#  '10.7.105.14',
#  '10.7.105.22',
#  '10.7.105.23',
#  '10.7.105.24',
#  '10.7.105.32',
#  '10.7.105.33',
#  '10.7.105.42',
#  '10.7.105.43',
#  '10.7.105.46',
#  '10.7.105.47',
#  '10.7.106.14',
#  '10.7.106.22',
#  '10.7.106.23',
#  '10.7.106.24',
#  '10.7.106.32',
#  '10.7.106.33',
#  '10.7.106.42',
#  '10.7.106.43',
#  '10.7.106.46',
#  '10.7.106.47'}


# IP adresy zo syslogu
# {'10.7.100.111',
#  '10.7.100.112',
#  '10.7.100.113',
#  '10.7.100.114',
#  '10.7.100.115',
#  '10.7.100.116',
#  '10.7.100.2',
#  '10.7.100.21',
#  '10.7.100.22',
#  '10.7.100.23',
#  '10.7.100.24',
#  '10.7.100.25',
#  '10.7.100.26',
#  '10.7.100.3',
#  '10.7.100.4',
#  '10.7.100.5',
#  '10.7.100.6',
#  '10.7.100.7',
#  '10.7.101.12',
#  '10.7.101.13',
#  '10.7.101.25',
#  '10.7.101.250',
#  '10.7.101.26',
#  '10.7.101.27',
#  '10.7.101.28',
#  '10.7.101.29',
#  '10.7.101.34',
#  '10.7.101.44',
#  '10.7.101.45',
#  '10.7.101.48',
#  '10.7.101.49',
#  '10.7.102.12',
#  '10.7.102.13',
#  '10.7.102.25',
#  '10.7.102.250',
#  '10.7.102.26',
#  '10.7.102.27',
#  '10.7.102.28',
#  '10.7.102.29',
#  '10.7.102.34',
#  '10.7.102.44',
#  '10.7.102.45',
#  '10.7.102.48',
#  '10.7.102.49',
#  '10.7.103.12',
#  '10.7.103.13',
#  '10.7.103.25',
#  '10.7.103.250',
#  '10.7.103.26',
#  '10.7.103.27',
#  '10.7.103.28',
#  '10.7.103.29',
#  '10.7.103.34',
#  '10.7.103.44',
#  '10.7.103.45',
#  '10.7.103.48',
#  '10.7.103.49',
#  '10.7.104.12',
#  '10.7.104.13',
#  '10.7.104.25',
#  '10.7.104.250',
#  '10.7.104.26',
#  '10.7.104.27',
#  '10.7.104.28',
#  '10.7.104.29',
#  '10.7.104.34',
#  '10.7.104.44',
#  '10.7.104.45',
#  '10.7.104.48',
#  '10.7.104.49',
#  '10.7.105.12',
#  '10.7.105.13',
#  '10.7.105.25',
#  '10.7.105.250',
#  '10.7.105.26',
#  '10.7.105.27',
#  '10.7.105.28',
#  '10.7.105.29',
#  '10.7.105.34',
#  '10.7.105.44',
#  '10.7.105.45',
#  '10.7.105.48',
#  '10.7.105.49',
#  '10.7.106.12',
#  '10.7.106.13',
#  '10.7.106.25',
#  '10.7.106.250',
#  '10.7.106.26',
#  '10.7.106.27',
#  '10.7.106.28',
#  '10.7.106.29',
#  '10.7.106.34',
#  '10.7.106.44',
#  '10.7.106.45',
#  '10.7.106.48',
#  '10.7.106.49'}

def create_ip_flows(ip_flow_filename='data_filtered/data_ipflow_filtered_start.json', start_timestamp=1553065200000,
                    end_timestamp=1553092200000):
    # counter = 0
    with open(ip_flow_filename, 'r') as jsonfile:
        for line in jsonfile.readlines():
            data = json.loads(line)
            # counter += 1
            if data["biFlowStartMilliseconds"] >= start_timestamp and data["biFlowEndMilliseconds"] < end_timestamp:
                # counter += 1
                create_connections_in_database(data["sourceIPv4Address"], data["destinationIPv4Address"],
                                               data["biFlowStartMilliseconds"],
                                               data["biFlowEndMilliseconds"])
    # return counter


def create_connections_in_database(src_ip, dst_ip, start, end):
    with(DRIVER.session()) as session:
        session.run(
            "MERGE (a:IP_ADDRESS {address: $first_ip}) "
            "MERGE (b:IP_ADDRESS {address: $second_ip}) "
            "CREATE (a)-[:COMMUNICATES_WITH {start: $start, end: $end}]->(b)",
            **{'first_ip': src_ip, 'second_ip': dst_ip, 'start': start, 'end': end})
    print("created")


flow_ips = ['9.66.11.12', '9.66.11.13', '9.66.11.14', '10.1.2.22', '10.1.2.23', '10.1.2.24', '10.1.2.25', '10.1.2.26',
            '10.1.2.28', '10.1.2.27', '10.1.2.29', '10.1.3.32', '10.1.3.33', '10.1.3.34', '10.1.4.46', '10.1.4.47',
            '10.1.4.48', '10.1.4.49', '10.1.4.42', '10.1.4.43', '10.1.4.44', '10.1.4.45', '4.122.55.111',
            '4.122.55.112', '4.122.55.113', '4.122.55.114', '4.122.55.115',
            #'4.122.55.116',
            '4.122.55.117',
            '4.122.55.2', '4.122.55.3', '4.122.55.4', '4.122.55.5', '4.122.55.6', '4.122.55.7', '4.122.55.21',
            '4.122.55.22', '4.122.55.23', '4.122.55.24', '4.122.55.25', '4.122.55.26', '4.122.55.250']


def obtain_link_prediction_metrics(first_ip, second_ip):
    with (DRIVER.session()) as session:
        result = session.run("MATCH (p1:IP_ADDRESS {address: $first_ip}) "
                             "MATCH (p2:IP_ADDRESS {address: $second_ip}) "
                             "RETURN gds.alpha.linkprediction.adamicAdar(p1, p2) AS score_aa, "
                             "gds.alpha.linkprediction.commonNeighbors(p1, p2) AS score_cn, "
                             "gds.alpha.linkprediction.preferentialAttachment(p1, p2) AS score_pa, "
                             "gds.alpha.linkprediction.resourceAllocation(p1, p2) AS score_ra, "
                             "gds.alpha.linkprediction.sameCommunity(p1, p2) AS score_sc, "
                             "gds.alpha.linkprediction.totalNeighbors(p1, p2) AS score_tn",
                             **{'first_ip': first_ip, 'second_ip': second_ip})
        return result.data()[0]


def measure_link_prediction(list_of_ips):
    function_result = []
    for first_ip in list_of_ips:
        for second_ip in list_of_ips:
            if first_ip == second_ip:
                continue

            # Adamic-Adar
            # with (DRIVER.session()) as session:
            #     result = session.run("MATCH (p1:IP_ADDRESS {address: $first_ip}) "
            #                          "MATCH (p2:IP_ADDRESS {address: $second_ip}) "
            #                          "RETURN gds.alpha.linkprediction.adamicAdar(p1, p2) AS score_aa, "
            #                          "gds.alpha.linkprediction.commonNeighbors(p1, p2) AS score_cn, "
            #                          "gds.alpha.linkprediction.preferentialAttachment(p1, p2) AS score_pa, "
            #                          "gds.alpha.linkprediction.resourceAllocation(p1, p2) AS score_ra, "
            #                          "gds.alpha.linkprediction.sameCommunity(p1, p2) AS score_sc, "
            #                          "gds.alpha.linkprediction.totalNeighbors(p1, p2) AS score_tn",
            #                          **{'first_ip': first_ip, 'second_ip': second_ip})
            lp_metrics = obtain_link_prediction_metrics(first_ip, second_ip)
            if lp_metrics['score_aa'] != 0:
                print("first: ", first_ip, ", second: ", second_ip, ", Adamic-Adar: ", lp_metrics['score_aa'],
                      ", Common Neighbors: ", lp_metrics['score_cn'], ", Pref. Att.: ", lp_metrics['score_pa'],
                      ", Res. Allocation: ", lp_metrics['score_ra'], ", Same Community: ", lp_metrics['score_sc'],
                      ", Tot. Neighbors: ", lp_metrics['score_tn'])
                function_result.append({"first": first_ip, "second": second_ip, "score_aa": lp_metrics['score_aa'],
                                        "score_cn": lp_metrics['score_cn'], "score_pa": lp_metrics['score_pa'],
                                        "score_ra": lp_metrics['score_ra'], "score_sc": lp_metrics['score_sc'],
                                        "score_tn": lp_metrics['score_tn']})
        print()
    return function_result


# TODO je potreba casove znamky, pocet hran medzi dvojicou vrcholov
def prevailing_outcoming_connections(first_ip, second_ip,
                                     ip_flow_filename='data_filtered/data_ipflow_filtered_start.json'):
    outcoming = 0
    incoming = 0
    with open(ip_flow_filename, 'r') as jsonfile:
        for line in jsonfile.readlines():
            data = json.loads(line)
            # counter += 1
            if data["sourceIPv4Address"] == first_ip: # and data["destinationIPv4Address"] == second_ip:
                outcoming += 1
            if data["destinationIPv4Address"] == first_ip: # data["sourceIPv4Address"] == second_ip and :
                incoming += 1
    print("Prevailing outcoming connections from ", first_ip, " to ", second_ip, ". Outcoming: ", outcoming,
          ", incoming: ", incoming)
    return outcoming > incoming


# 1.) Klasifikator klasifikuje typy devices
# 2.) Podla Page Ranku sa urcia najdolezitejsie zariadenia, tu global-web a global-dns
# 3.) Podla link prediction sa predpovie, ake zavislosti sa v buducnosti vytvoria - tie su neorientovane,
# pokial node zvykne odpovedat na prichadzajuce spojenia alebo vysielat spojenia, tak dame smer, inak nechame
# neorientovanu hranu


def get_pagerank_results(relationship_name='COMMUNICATES_WITH'):
    page_rank_result = []
    with (DRIVER.session()) as session:
        page_rank = session.run("CALL gds.pageRank.stream( "
                             "{ "
                             "nodeProjection: 'IP_ADDRESS', "
                             f"relationshipProjection: '{relationship_name}' "
                             "} "
                             ") "
                             "YIELD nodeId, score "
                             "RETURN gds.util.asNode(nodeId).address AS address, score "
                             "ORDER BY score DESC, address ASC")
        page_rank_result = page_rank.data()
    return page_rank_result


def compute_dependencies(list_of_ips):
    ckt_results = {}
    ips_to_be_processed = []
    page_rank_result = get_pagerank_results()
    ip_addresses = [item['address'] for item in page_rank_result]
    scores = [item['score'] for item in page_rank_result]
    print("page rank result", page_rank_result)

    x, y, value = find_elbow(range(0, len(ip_addresses)), scores)
    print("x: ", x, ", y: ", y, ", value: ", value)
    for list_item in page_rank_result:
        # print("list_item", list_item)
        if list_item['score'] >= y:
            ips_to_be_processed.append(list_item['address'])
            ckt_results[list_item['address']] = list_item['score']

    # print("ips to be processed", ips_to_be_processed)
    while ips_to_be_processed:
        # print("ips to be processed: ", ips_to_be_processed)
        current_ip = ips_to_be_processed.pop(0)
        print("current_ip is", current_ip)
        lp_metrics_results = {}
        for second_ip in list_of_ips:
            if second_ip != current_ip:
                lp_metrics = obtain_link_prediction_metrics(current_ip, second_ip)
                lp_metrics_results[second_ip] = lp_metrics['score_aa']
        lp_metrics_sorted = {key: value for key, value in sorted(lp_metrics_results.items(),
                                                                 key=lambda item: item[1], reverse=True)}
        print(lp_metrics_sorted)
        current_x, current_y, current_value = find_elbow(list(range(0, len(lp_metrics_sorted.keys()))),
                                                         list(lp_metrics_sorted.values()))
        print("elbow is: ", current_x, current_y, current_value)
        for second_ip in lp_metrics_sorted:
            if lp_metrics_sorted[second_ip] >= current_y:
                create_dependency_in_database(current_ip, second_ip, lp_metrics_sorted[second_ip])
                if second_ip not in ckt_results:
                    ips_to_be_processed.append(second_ip)
                    ckt_results[second_ip] = lp_metrics_sorted[second_ip]


def compute_ckt():
    page_rank_result = get_pagerank_results()
    pprint(page_rank_result)

    ckt = {}
    for list_item in page_rank_result:
        # list_item['address']
        if list_item['score'] >= 8.5: # write elbow here
            ckt[list_item['address']] = list_item['score']
            print(list_item)
    print(ckt)

    # TODO pribudli ďalšie metriky
    for list_item in measure_link_prediction(flow_ips):
        first_ip = list_item['first']
        second_ip = list_item['second']
        if first_ip in ckt:
            # TODO opravit, lebo toto nebude fungovat, napr. lokalny DNS5 ma takmer o 8000 viacej outgoing ako
            # incoming connections a global DNS ma zasa takmer o 27 000 viacej incoming connections
            if prevailing_outcoming_connections(first_ip, second_ip) and \
                    list_item['score_aa']*ckt[list_item['address']] >= 8.5:
                    # list_item['score_aa'] >= 0.2:
                ckt[second_ip] = list_item['score_aa']
    print(ckt)

    # for list_item in measure_link_prediction(flow_ips):
    #     first_ip = list_item['first']
    #     second_ip = list_item['second']
    #     if first_ip in ckt:
    #         if list_item['score_aa'] >= 1 and prevailing_outcoming_connections(first_ip, second_ip):
    #             ckt[second_ip] = list_item['score_aa']
    # print(ckt)


# TODO pozorvanie
# PageRank určí poradie IP adries podľa vzájomných odkazov, na prvých miestach globálny DNS, global web, lokálny DNS4,
# lokálny DNS2, potom sa to začína miešať s devices, kt. by sme možno nechceli, ale stále tam je veľa zariadení z CKT
# napr. admin, monitoring, lokálny web4, Google DNS, ...

# TODO pridat time series link prediction, pretoze stratime casovu informaciu
#  https://ieeexplore.ieee.org/document/6252471

# pagerank - influence or importance of nodes in a directed graph
# articlerank - ako pagerank, ale measures transitive influence or connectivity of nodes
# nepodarilo sa spočítať kvôli halde
# betweenness centrality  - amount of influence a node has over the flow of information in a graph
# betweenness centrality s absolútnou hodnotou centrality, dáva ešte lepší prehľad zoradených top n zariadení
# degree centrality - find popularity of individual nodes, extract fraudsters from legitimate users
# degree centrality nedáva až také dobré výsledky ako betweenness pri zoradení DESC
# closeness centrality dáva nanič výsledky
# eigenvector centrality - nepodarilo sa spočítať kvôli halde

# Backupy jednotlivých Neo4j queries
# CALL gds.alpha.articleRank.stream({nodeProjection: 'IP_ADDRESS', relationshipProjection: 'COMMUNICATES_WITH',
# maxIterations: 20, dampingFactor: 0.85}) YIELD nodeId, score RETURN gds.util.asNode(nodeId).address AS
# address, score ORDER BY score DESC, address ASC
#
# CALL gds.alpha.betweenness.stream({nodeProjection: 'IP_ADDRESS', relationshipProjection: {COMMUNICATES_WITH:
# {type: 'COMMUNICATES_WITH', orientation: 'NATURAL'}}}) YIELD nodeId, centrality
# RETURN gds.util.asNode(nodeId).address AS address, abs(centrality) ORDER BY abs(centrality) DESC, address ASC
#
# CALL gds.alpha.degree.stream({nodeProjection: 'IP_ADDRESS', relationshipProjection: {COMMUNICATES_WITH:
# {type: 'COMMUNICATES_WITH', orientation: 'NATURAL'}}}) YIELD nodeId, score
# RETURN gds.util.asNode(nodeId).address AS address, score ORDER BY score DESC, address ASC

# Link prediction metrics
# Adamic Adar - closeness of nodes based on their shared neighbors
# Common Neighbors -  two strangers who have a friend in common are more likely to be introduced
# Preferential Attachment - closeness of nodes, based on their shared neighbors
# Resource Allocation - closeness of nodes based on their shared neighbors
# Same Community - 0 indicates different community, 1 indicates that two nodes are in the same community
# Total Neighbors - closeness of nodes, based on the number of unique neighbors that they have.
#                   It is based on the idea that the more connected a node is, the more likely
#                   it is to receive new links. E.g., DNS?
#
# Vzorce pre LP metriky
# Adamic Adar a Resource Allocation majú podobný vzorec, iba Adamic Adar má logaritmus. Obidva vyjadrujú, že
# keď majú x, y spoločných susedov, tak ich blízkosť je tým vyššia, čím menší počet susedov majú ich susedia okrem
# ich samotných. x, y sú unikátnejšie k sebe "zviazané".
# Common Neighbors - čím viac spoločných susedov majú, tým sú si x,y bližšími vrcholmi.
# Preferential Attachment - čím viac susedov majú v súčine x aj y, tým sú si bližšími vrcholmi.
# Total Neighbors - čím viac unikátnych susedov majú v súčte x aj y, tým je pravdepodobnejšie ich spojenie.

# mission critical devices majú spravidla veľa source IPs, kt. na ne komunikujú zo siete

# MATCH (ip1:IP_ADDRESS)-[r:COMMUNICATES_WITH]->(ip2:IP_ADDRESS) WHERE r.end <= 1553008187739
# AND r.start >= 1552994894805 AND (ip1.address STARTS WITH '10.' OR ip1.address STARTS WITH '4.122.'
# OR ip1.address STARTS WITH '9.66.') AND (ip2.address STARTS WITH '10.' OR ip2.address STARTS WITH '4.122.'
# OR ip2.address STARTS WITH '9.66.') RETURN DISTINCT ip1.address, ip2.address

# Pri vyfiltrovani pomocou
# CALL gds.alpha.betweenness.stream({nodeQuery: 'MATCH (n) RETURN id(n) AS id', relationshipQuery:
# "MATCH (ip1:IP_ADDRESS)-[r:COMMUNICATES_WITH]->(ip2:IP_ADDRESS) WHERE r.end <= 1553008187739  AND r.start >=
# 1552994894805 AND ip1.address STARTS WITH '10.' OR ip1.address STARTS WITH '4.122.' OR ip1.address STARTS WITH
# '9.66.' RETURN DISTINCT id(ip1) AS source, id(ip2) AS target"}) YIELD nodeId, centrality RETURN
# gds.util.asNode(nodeId).address AS address, abs(centrality) ORDER BY abs(centrality) DESC, address ASC
# majú popredné pozície prakticky iba mission-critical devices. Všetko ostatné, napr. desktop, má nulovú centralitu.

# Pri aplikovani PageRanku na ten isty subgraph dostanem horsi zoznam, kt. obsahuje na poprednych poziciach monitoring,
# a obcas aj nejakeho admina alebo desktop este pred local DNS alebo web

# RQ1: betweenness centrality - zmerat, ake uspesne je pri urcovani toho, co by mohlo byt critical?
# RQ2: casove serie + link prediction - na urcenie zavislosti
# RQ3: urcenie typu sluzby cisto na zaklade hodnot tychto metrik - napr. priemerna hodnota Adamic-Adar indexu
# vzhladom k vsetkym dalsim moznym susedom

# Pri vyfiltrovaní dát, kt. majú src a dst IP začínajúcu '4.122.', '9.' a '10.' dáva PageRank veľmi dobré výsledky v
# porovnaní s betweenness centrality, lebo tá uprednostňuje desktopy a adminov pred lokálnymi DNS serverami.

def find_elbow(x_values, y_values):
    # Vykreslime si hodnoty PageRanku pre jednotlive IP adresy do scree plotu, kde sa hodnoty
    # PageRanku zoradia zlava doprava. Potom elbow rule hlada zlom, kde sa uz vyraznejsie nezlepsi
    # situacia, ked pridame do vysledneho setu dalsiu IP adresu. Napr. pri clusteringu sa tak hlada
    # K pre K means ako optimalny pocet clusterov, kde sa vysvetli najviac variancie. Tu sa to
    # interpretuje ako zlom, kedy uz dalsia IP adresa nepatri podla nameranych dat medzi kriticke
    # zariadenia.
    # Mozno by bolo lepsie zobrat 100/pocet_vrcholov ako treshold

    # find_elbow(list(range(0, 42)),
    #            [20.62647748924792, 12.53251598738134, 5.84445391166955, 3.5142225843854247, 2.2400486109778286,
    #             1.9600733295083048, 1.912588862422854, 1.7032109023537487, 1.7032109023537487,
    #             1.7032109023537487, 1.7032109023537487, 1.7032109023537487, 1.7032109023537487, 1.6993320974055681,
    #             1.588838569028303, 1.5663351750932633, 1.542579449899495, 1.266422344464809,
    #             1.1819780226098373, 0.9978374485624958, 0.9961600645910947, 0.9670543998479844, 0.9670543998479844,
    #             0.9089744182303549, 0.8859731738222762, 0.8792908591218292, 0.7950929156504571,
    #             0.7393529727589341, 0.6932658981066198, 0.6932658981066198, 0.6932658981066198, 0.6698968957760372,
    #             0.6698968957760372, 0.6698968957760372, 0.6698968957760372, 0.6698968957760372,
    #             0.6698968957760372, 0.6698968957760372, 0.6698968957760372, 0.6698968957760372, 0.6698968957760372,
    #             0.6698968957760372, 0.6698968957760372])

    # TODO toto by fungovalo, keby x bolo numerického typu
    # x_values = range(0, n)
    # prevzate z https://stackoverflow.com/questions/2018178/finding-the-best-trade-off-point-on-a-curve
    # max_x_x = max(x_values)
    # print("max_x_x", max_x_x)
    # max_x_y = y_values[max_x_x-1]
    # print("max_x_y", max_x_y)
    # max_y_y = max(y_values)
    # print("max_y_y", max_y_y)
    # max_y_x = y_values.index(max_y_y)
    # print("max_y_x", max_y_x)
    # highest_value_x = 0
    # highest_value_y = 0
    # highest_distance = 0
    #
    # for x_current in x_values:
    #     if x_current != max_x_x and x_current != max_y_x:
    #         # line: (max_x_x, max_x_y), (max_y_x, max_y_y)
    #         # point: (x_current, y_values[x_current])
    #         distance = abs((max_y_x-max_x_x)*(max_x_y-y_values[x_current]) - (max_x_x-x_current)*(max_y_y-max_x_y)) \
    #                    / sqrt((max_y_x-max_x_x)*(max_y_x-max_x_x) + (max_y_y-max_x_y)*(max_y_y-max_x_y))
    #         # distance = abs((x_current - max_x_x) * (max_x_y - max_y_y) - (max_x_x - max_y_x) * (y_values[x_current] - max_x_y)) \
    #         #            / sqrt((x_current - max_x_x)*(x_current - max_x_x) +
    #         #                   (y_values[x_current] - max_x_y)*(y_values[x_current] - max_x_y))
    #         if distance > highest_distance:
    #             highest_distance = distance
    #             highest_value_x = x_current
    #             highest_value_y = y_values[x_current]
    # print(highest_value_x, highest_value_y)

    # https://stackoverflow.com/questions/4471993/compute-the-elbow-for-a-curve-automatically-and-mathematically
    # vzorec pre second derivative bol odvodený z Taylorovych rad
    # secondDerivative[i] = f(x[i + 1]) + f(x[i - 1]) - 2 * f(x[i])
    # Tento vzorec je lepsi, lebo ked to pustime do nekonecna, tak tam existuju hocijake "mensie elbows"
    # https://en.wikipedia.org/wiki/Knee_of_a_curve - optimization
    min_x = x_values[0]
    max_x = x_values[len(x_values)-1]
    highest_derivative_x = 0
    highest_derivative_y = 0
    highest_derivative_value = 0

    for x_current in x_values:
        if x_current != min_x and x_current != max_x:
            derivative = y_values[x_current+1] + y_values[x_current-1] - 2 * y_values[x_current]
            if derivative > highest_derivative_value:
                highest_derivative_value = derivative
                highest_derivative_x = x_current
                highest_derivative_y = y_values[x_current]
    return highest_derivative_x, highest_derivative_y, highest_derivative_value


# Pozorovanie - predstavme si, ze web server 9.66.11.14. je mission-critical. Potom jeho zavislosti sa daju na zaklade
# link prediction metrics odvodit?
# Dalej - vezmi hosta - k nemu adamic adar metrics pre vsetkych a nejako urci treshold / elbow.


def evaluate_link_prediction_metrics(list_of_ips):
    for first_ip in list_of_ips:
        # IPs that can be connected with the first IP contain in the dictionary value of Adamic Adar index
        adamic_adar_values = {}
        for second_ip in list_of_ips:
            with (DRIVER.session()) as session:
                result = session.run("MATCH (p1:IP_ADDRESS {address: $first_ip}) "
                                     "MATCH (p2:IP_ADDRESS {address: $second_ip}) "
                                     "RETURN gds.alpha.linkprediction.adamicAdar(p1, p2) AS score_aa",
                                     **{'first_ip': first_ip, 'second_ip': second_ip})
                lp_metrics = result.data()[0]
                adamic_adar_values[second_ip] = lp_metrics['score_aa']
        adamic_adar_values = {key: value for key, value in sorted(adamic_adar_values.items(),
                                                                  key=lambda item: item[1], reverse=True)}
        print("First IP: ", first_ip)
        print(adamic_adar_values)
        x, y, value = find_elbow(list(range(0, len(adamic_adar_values.keys()))), list(adamic_adar_values.values()))
        print("Elbow's x: ", x, ", y: ", y, ", value: ", value)
        print()

        counter = 0
        for key in adamic_adar_values:
            value = adamic_adar_values[key]
            if value < y or counter > x:
                break
            else:
                create_dependency_in_database(first_ip, key, value)
                counter += 1
        print()

        # TODO ELBOW METHOD sa mi zdala nic moc, skusil by som ine optimalizacne kriterium
        # mozno by som skusil este casove znamky


def create_dependency_in_database(src_ip, dst_ip, score):
    with(DRIVER.session()) as session:
        session.run(
            "MERGE (a:IP_ADDRESS {address: $first_ip}) "
            "MERGE (b:IP_ADDRESS {address: $second_ip}) "
            "CREATE (a)-[:DEPENDENCY {score: $score}]->(b)",
            **{'first_ip': src_ip, 'second_ip': dst_ip, 'score': score})
    print("created src_ip: ", src_ip, ", dst_ip: ", dst_ip, ", score: ", score)


def create_reversed_dependencies():
    for first_ip in adamic_adar_results:
        for second_ip in adamic_adar_results[first_ip]:
            create_dependency_in_database(second_ip, first_ip, adamic_adar_results[first_ip][second_ip])


# Toto nie su nezmysly, pretoze chybaju data z vnutornych subnetov, t.j. komunikacia v ramci BT subnetu
# v realnej sieti to tak nemusi byt
adamic_adar_results = {
    "9.66.11.12": {'9.66.11.13': 3.1682154206892323, '9.66.11.14': 2.586802299994103},
    "9.66.11.13": {'9.66.11.12': 3.1682154206892323, '4.122.55.22': 2.8070460510310404},
    "9.66.11.14": {'10.1.4.47': 9.147005199398548, '10.1.4.43': 6.919378992728976, '10.1.4.46': 4.782228804505263},
    "10.1.2.22": {'10.1.4.47': 4.415580079596388, '10.1.4.43': 4.310418633997334, '10.1.3.33': 3.8612518229201345,
                  '9.66.11.14': 3.2407604615497743, '10.1.4.42': 3.2281994373085494, '10.1.4.46': 3.1782831321068272,
                  '10.1.2.24': 2.925119592595049, '4.122.55.22': 2.277961128875081, '4.122.55.23': 2.277961128875081,
                  '4.122.55.24': 2.277961128875081, '4.122.55.25': 2.277961128875081, '4.122.55.26': 2.277961128875081},
    "10.1.2.23": {'10.1.2.24': 3.4852775369971383, '10.1.4.47': 2.4675903302213853},
    "10.1.2.24": {'10.1.4.47': 3.8274192308486765, '10.1.2.23': 3.4852775369971383},
    "10.1.2.25": {'10.1.2.29': 9.05518040943069, '10.1.2.27': 4.797597233185232},
    "10.1.2.26": {'10.1.2.29': 6.008212451342451, '10.1.2.25': 4.654271825137077, '10.1.2.27': 3.538104344000742},
    "10.1.2.27": {'10.1.2.29': 4.981683804969308, '10.1.2.25': 4.797597233185232, '10.1.2.26': 3.538104344000742},
    "10.1.2.28": {'4.122.55.3': 2.6935481186232573, '4.122.55.22': 2.6935481186232573,
                  '4.122.55.23': 2.6935481186232573, '4.122.55.24': 2.6935481186232573,
                  '4.122.55.25': 2.6935481186232573, '4.122.55.26': 2.6935481186232573,
                  '10.1.2.26': 2.4947582685890484, '10.1.2.29': 2.3475451156005405, '10.1.4.44': 2.321476506881426,
                  '10.1.2.25': 2.1293718538539954, '10.1.4.45': 1.9552469287411776},
    "10.1.2.29": {'10.1.2.25': 9.05518040943069, '10.1.2.26': 6.008212451342451},
    "10.1.3.32": {'10.1.4.47': 7.116217373516253, '10.1.4.43': 6.936811145854096, '10.1.4.42': 4.941977795996864},
    "10.1.3.33": {'10.1.4.43': 4.976421389175525, '10.1.4.46': 4.694651763712206, '10.1.3.32': 4.587899886474319,
                  '10.1.4.47': 4.471131235561043, '10.1.4.42': 4.101733484447008, '10.1.2.22': 3.8612518229201345,
                  '9.66.11.14': 2.540102432724444},
    "10.1.3.34": {'10.1.4.46': 2.1417888752074465, '4.122.55.22': 2.010460716071996},
    "10.1.4.42": {'10.1.4.47': 22.1513186996019, '10.1.4.46': 18.71499386544565, '10.1.4.43': 17.245466624235068,
                  '10.1.3.32': 4.941977795996864},
    "10.1.4.43": {'10.1.4.46': 42.568166834420055, '10.1.4.47': 24.46168299793246},
    "10.1.4.44": {'10.1.4.49': 4.311743877782548, '10.1.4.48': 4.095064812447016, '10.1.2.26': 3.5042677122670893,
                  '10.1.2.29': 3.3631861999352384, '10.1.2.25': 3.3508034424340716, '10.1.2.27': 3.017991664556138,
                  '10.1.4.45': 2.754208947740344, '4.122.55.3': 2.657991134618569, '4.122.55.22': 2.657991134618569,
                  '4.122.55.23': 2.657991134618569, '4.122.55.24': 2.657991134618569, '4.122.55.25': 2.657991134618569,
                  '4.122.55.26': 2.657991134618569, '10.1.2.28': 2.321476506881426, '9.66.11.12': 1.5434379354683256,
                  '9.66.11.13': 1.5434379354683256},
    "10.1.4.45": {'10.1.4.49': 4.1173941811402885, '10.1.4.48': 3.9007151158047564, '10.1.2.25': 3.0276552641160857},
    "10.1.4.46": {'10.1.4.43': 42.568166834420055, '10.1.4.47': 41.5250685692135, '10.1.4.42': 18.71499386544565,
                  '9.66.11.14': 4.782228804505263},
    "10.1.4.47": {'10.1.4.46': 41.5250685692135, '10.1.4.43': 24.46168299793246},
    "10.1.4.48": {'10.1.4.44': 4.095064812447016, '10.1.4.45': 3.9007151158047564, '10.1.2.29': 3.1677799797403634},
    "10.1.4.49": {'10.1.4.44': 4.311743877782548, '10.1.4.45': 4.1173941811402885, '10.1.2.29': 3.1095514673334015},
    "4.122.55.111": {'4.122.55.114': 3.408003551292032, '4.122.55.5': 2.9355895767401483,
                     '4.122.55.22': 2.776655486349989, '4.122.55.24': 2.776655486349989,
                     '4.122.55.25': 2.776655486349989, '4.122.55.112': 2.757834812746949,
                     '4.122.55.21': 2.6747186945373804, '4.122.55.23': 2.6251060991075854,
                     '4.122.55.26': 2.6251060991075854, '4.122.55.6': 2.501653732171224,
                     '4.122.55.117': 2.4960429238406094, '4.122.55.3': 2.2873296599401285,
                     '4.122.55.115': 2.1845616127048864, '4.122.55.2': 2.1210324004570342,
                     '4.122.55.4': 2.0754075150380933, '4.122.55.113': 1.9864272890823182,
                     '4.122.55.7': 1.9653085104030685, '4.122.55.250': 1.9653085104030685,
                     '10.1.4.46': 1.5947276624878652, '10.1.4.47': 1.5947276624878652},
    "4.122.55.112": {'4.122.55.111': 2.757834812746949, '4.122.55.5': 2.530885614246722,
                     '4.122.55.6': 2.530885614246722, '4.122.55.3': 2.5074343100225596,
                     '4.122.55.117': 2.447315545509061, '4.122.55.21': 2.404091268084542,
                     '4.122.55.22': 2.404091268084542, '4.122.55.24': 2.404091268084542,
                     '4.122.55.25': 2.404091268084542, '4.122.55.2': 2.3745264988136503,
                     '4.122.55.115': 2.291558124427304, '4.122.55.114': 2.2588802893352242,
                     '4.122.55.23': 2.252541880842138, '4.122.55.26': 2.252541880842138,
                     '4.122.55.4': 2.216227633802597, '4.122.55.250': 2.216227633802597,
                     '4.122.55.113': 2.093423800804736, '4.122.55.7': 1.9653085104030685,
                     '10.1.4.42': 1.578422146505566},
    "4.122.55.113": {'4.122.55.21': 3.040056171912512, '4.122.55.22': 3.040056171912512,
                     '4.122.55.24': 3.040056171912512, '4.122.55.25': 3.040056171912512,
                     '4.122.55.115': 2.927523028255275, '4.122.55.5': 2.9207795179382368,
                     '4.122.55.23': 2.8885067846701085, '4.122.55.26': 2.8885067846701085,
                     '4.122.55.117': 2.8666013840015, '4.122.55.3': 2.6305052963065365,
                     '4.122.55.4': 2.6305052963065365},
    "4.122.55.114": {'4.122.55.111': 3.408003551292032, '4.122.55.3': 2.532883091148787},
    "4.122.55.115": {'4.122.55.21': 3.238190495535081, '4.122.55.22': 3.238190495535081,
                     '4.122.55.24': 3.238190495535081, '4.122.55.25': 3.238190495535081,
                     '4.122.55.3': 3.086957386736434, '4.122.55.23': 3.086641108292677,
                     '4.122.55.26': 3.086641108292677, '4.122.55.117': 3.0647357076240684,
                     '4.122.55.113': 2.927523028255275, '4.122.55.5': 2.919602654518302,
                     '4.122.55.4': 2.828639619929105, '4.122.55.6': 2.8095036498832773,
                     '4.122.55.2': 2.7185406152940805, '4.122.55.250': 2.7185406152940805,
                     '4.122.55.7': 2.467621491894552},
    "4.122.55.117": {'4.122.55.21': 3.332992741335272, '4.122.55.22': 3.332992741335272,
                     '4.122.55.24': 3.332992741335272, '4.122.55.25': 3.332992741335272,
                     '4.122.55.23': 3.1814433540928677, '4.122.55.26': 3.1814433540928677,
                     '4.122.55.115': 3.0647357076240684, '4.122.55.113': 2.8666013840015,
                     '4.122.55.250': 2.8630617902290645, '4.122.55.5': 2.8586810102645273,
                     '4.122.55.2': 2.8133428610942715, '4.122.55.3': 2.7677179756753305,
                     '4.122.55.4': 2.7677179756753305, '4.122.55.6': 2.7485820056295025,
                     '4.122.55.111': 2.4960429238406094, '4.122.55.112': 2.447315545509061,
                     '4.122.55.7': 2.4066998476407773, '4.122.55.114': 2.3235402969572463,
                     '10.1.2.29': 1.8793130497888935},
    "4.122.55.2": {'4.122.55.3': 5.479203093862012, '4.122.55.22': 3.8187487181851627},
    "4.122.55.3": {'4.122.55.2': 5.484617437405683, '4.122.55.5': 5.035453118331749, '4.122.55.7': 4.884321720673894,
                   '4.122.55.24': 4.86835769974308, '4.122.55.22': 4.864680370430526, '4.122.55.25': 4.864680370430526,
                   '4.122.55.23': 4.513555491996767, '4.122.55.26': 4.513555491996767, '4.122.55.4': 3.88318113591417,
                   '4.122.55.250': 3.596387521794313, '4.122.55.6': 3.4656633150594787, '10.1.2.29': 3.257242162419005,
                   '4.122.55.115': 2.991234558095348, '4.122.55.21': 2.9554352880346837,
                   '4.122.55.117': 2.6719951470342447, '10.1.2.26': 2.634412895500349,
                   '10.1.2.28': 2.5978252899821714, '10.1.4.44': 2.562268305977484,
                   '4.122.55.113': 2.5347824676654507, '4.122.55.112': 2.5074343100225596,
                   '4.122.55.114': 2.4371602625077013, '9.66.11.13': 2.3740662658256424,
                   '4.122.55.111': 2.2873296599401285, '10.1.2.25': 2.2690264807652962,
                   '10.1.4.45': 2.1960387278372355, '9.66.11.12': 2.1785589040304956, '10.1.4.48': 2.094199551654944,
                   '10.1.4.49': 2.094199551654944, '10.1.2.27': 2.066938909622197, '9.66.11.14': 2.0498843133284734,
                   '10.1.3.34': 1.5631067273353256},
    "4.122.55.4": {'4.122.55.3': 3.8365119976633073, '4.122.55.2': 3.5497183835434507,
                   '4.122.55.250': 3.5497183835434507, '4.122.55.5': 3.529093181443641,
                   '4.122.55.7': 3.4754938696287545, '4.122.55.6': 3.4189941768086163,
                   '4.122.55.22': 2.932861654815076, '4.122.55.24': 2.932861654815076,
                   '4.122.55.25': 2.932861654815076},
    "4.122.55.5": {'4.122.55.3': 5.025467802322624, '4.122.55.6': 3.9920232208185094, '4.122.55.4': 3.5657770036853784,
                   '4.122.55.2': 3.4556779990503537, '4.122.55.250': 3.4556779990503537,
                   '4.122.55.7': 3.4242943859515322, '4.122.55.22': 3.3843453515799093,
                   '4.122.55.24': 3.3843453515799093, '4.122.55.25': 3.3843453515799093,
                   '4.122.55.23': 3.2327959643375053, '4.122.55.26': 3.2327959643375053,
                   '4.122.55.21': 3.148327701646619, '4.122.55.111': 2.9355895767401483,
                   '4.122.55.113': 2.815071373288026, '4.122.55.115': 2.8138945098680908,
                   '4.122.55.117': 2.752972865614316, '4.122.55.114': 2.4271749464985763,
                   '4.122.55.112': 2.4251774695965107, '10.1.2.29': 1.6428806984038484},
    "4.122.55.6": {'4.122.55.5': 3.952520386719403, '4.122.55.2': 3.4161751649512473, '4.122.55.3': 3.4161751649512473,
                   '4.122.55.4': 3.4161751649512473, '4.122.55.250': 3.4161751649512473,
                   '4.122.55.7': 3.3104670203010365, '4.122.55.22': 2.910906672911879,
                   '4.122.55.24': 2.910906672911879, '4.122.55.25': 2.910906672911879,
                   '4.122.55.21': 2.7768258147911973, '4.122.55.23': 2.759357285669475,
                   '4.122.55.26': 2.759357285669475, '4.122.55.115': 2.6642926711339596,
                   '4.122.55.117': 2.6033710268801853, '4.122.55.111': 2.501653732171224,
                   '4.122.55.113': 2.4661583475113913, '4.122.55.112': 2.3856746354974043,
                   '4.122.55.114': 2.309131450586314, '10.1.2.29': 1.6033778643047418},
    "4.122.55.7": {'4.122.55.3': 4.849320342580145, '4.122.55.4': 3.4871616297858687},
    "4.122.55.21": {'4.122.55.22': 4.558293648646308, '4.122.55.24': 4.558293648646308,
                    '4.122.55.25': 4.558293648646308, '4.122.55.23': 4.4067442614039045,
                    '4.122.55.26': 4.4067442614039045, '4.122.55.2': 3.2641147935698958},
    "4.122.55.22": {'4.122.55.24': 6.947563438467948, '4.122.55.25': 6.947563438467948,
                    '4.122.55.23': 6.796014051225544, '4.122.55.26': 6.796014051225544,
                    '4.122.55.3': 4.759188396880689},
    "4.122.55.23": {'4.122.55.22': 6.792108950835091, '4.122.55.24': 6.792108950835091,
                    '4.122.55.25': 6.792108950835091, '4.122.55.26': 6.792108950835091,
                    '4.122.55.21': 4.405180281894494},
    "4.122.55.24": {'4.122.55.22': 6.946707414401106, '4.122.55.25': 6.946707414401106,
                    '4.122.55.23': 6.795158027158702, '4.122.55.26': 6.795158027158702,
                    '4.122.55.3': 4.762009702126401},
    "4.122.55.25": {'4.122.55.22': 6.948120348512237, '4.122.55.24': 6.948120348512237,
                    '4.122.55.23': 6.796570961269833, '4.122.55.26': 6.796570961269833,
                    '4.122.55.3': 4.759745306924978},
    "4.122.55.26": {'4.122.55.22': 6.792744475352517, '4.122.55.23': 6.792744475352517,
                    '4.122.55.24': 6.792744475352517, '4.122.55.25': 6.792744475352517,
                    '4.122.55.21': 4.405815806411921},
    "4.122.55.250": {'4.122.55.2': 3.547240399739303, '4.122.55.3': 3.547240399739303,
                     '4.122.55.4': 3.547240399739303, '4.122.55.5': 3.4165161930044685,
                     '4.122.55.6': 3.4165161930044685, '4.122.55.7': 3.2963212763397745,
                     '4.122.55.22': 2.8202846663759034, '4.122.55.24': 2.8202846663759034,
                     '4.122.55.25': 2.8202846663759034}
}


# TODO najdi CKT pre vstupne zariadenie, napr. webserver, dependencies su v zasade celkom dobre urcene,
#  nevyhoda je, ze Adamic Adar je undirected
# TODO pozriet sa na zariadenia, s kt. komunikoval host najviac a to takisto zaradit, napr. pre 9.66.11.12 by podla
#  priamej komunikacie bolo dobre zvazit aj 4.122.55.5 alebo 4.122.55.3?
# First IP:  9.66.11.12
# {'9.66.11.13': 3.1682154206892323, '9.66.11.14': 2.586802299994103, '4.122.55.22': 2.352923866316978, '4.122.55.23': 2.352923866316978, '4.122.55.24': 2.352923866316978, '4.122.55.25': 2.352923866316978, '4.122.55.26': 2.352923866316978, '4.122.55.3': 2.2742817326715814, '10.1.2.29': 2.0728282924361134, '4.122.55.21': 1.9187565607303823, '10.1.4.46': 1.6591300616795115, '10.1.4.47': 1.6591300616795115, '4.122.55.117': 1.6082852280026443, '10.1.2.22': 1.5491447085900847, '10.1.2.25': 1.5434379354683256, '10.1.2.27': 1.5434379354683256, '10.1.4.48': 1.5434379354683256, '10.1.4.49': 1.5434379354683256, '10.1.4.44': 1.5434379354683256, '10.1.4.45': 1.5434379354683256, '10.1.2.26': 1.4546334385235433, '4.122.55.5': 1.4368788226532314, '4.122.55.250': 1.4204215937206994, '10.1.2.28': 1.4180458330053654, '4.122.55.113': 1.4028424088138856, '4.122.55.114': 1.4028424088138856, '4.122.55.115': 1.4028424088138856, '10.1.4.42': 1.3567066038811884, '4.122.55.112': 1.3071195801727997, '10.1.3.34': 1.2532012628524414, '4.122.55.111': 1.2354478493619347, '4.122.55.2': 1.2149787745319407, '4.122.55.4': 1.2149787745319407, '4.122.55.6': 1.2149787745319407, '10.1.3.33': 1.1254624962725082, '10.1.4.43': 1.1254624962725082, '4.122.55.7': 1.1092706298817299, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.3.32': 1.013547801240644, '9.66.11.12': 0.0}
# Elbow's x:  1 , y:  2.586802299994103 , value:  0.3475346870180047

# First IP:  9.66.11.13
# {'9.66.11.12': 3.1682154206892323, '4.122.55.22': 2.8070460510310404, '4.122.55.23': 2.8070460510310404, '4.122.55.24': 2.8070460510310404, '4.122.55.25': 2.8070460510310404, '4.122.55.26': 2.8070460510310404, '9.66.11.14': 2.6668359169155993, '4.122.55.3': 2.4697890944667282, '4.122.55.21': 2.2709419536318363, '10.1.4.47': 2.1593019695916658, '10.1.4.46': 2.1545292721363363, '10.1.2.29': 2.0728282924361134, '10.1.4.43': 1.8625408200058822, '10.1.4.42': 1.8188773498720687, '10.1.3.34': 1.7073234475665038, '10.1.2.22': 1.6760657713218778, '4.122.55.5': 1.6323861844483782, '4.122.55.113': 1.6063983318858504, '4.122.55.114': 1.6063983318858504, '4.122.55.115': 1.6063983318858504, '4.122.55.117': 1.6063983318858504, '10.1.3.33': 1.5876332422633888, '10.1.2.25': 1.5434379354683256, '10.1.2.27': 1.5434379354683256, '10.1.4.48': 1.5434379354683256, '10.1.4.49': 1.5434379354683256, '10.1.4.44': 1.5434379354683256, '10.1.4.45': 1.5434379354683256, '4.122.55.112': 1.5106755032447645, '10.1.3.32': 1.4757185472315246, '10.1.2.26': 1.4465848772467254, '4.122.55.111': 1.4309552111570816, '4.122.55.2': 1.4185346976039057, '4.122.55.4': 1.4185346976039057, '4.122.55.6': 1.4185346976039057, '4.122.55.250': 1.4185346976039057, '10.1.2.28': 1.4099972717285474, '4.122.55.7': 1.3128265529536947, '10.1.2.23': 1.1404688639724372, '10.1.2.24': 1.1404688639724372, '9.66.11.13': 0.0}
# Elbow's x:  1 , y:  2.8070460510310404 , value:  0.36116936965819235

# First IP:  9.66.11.14
# {'10.1.4.47': 9.147005199398548, '10.1.4.43': 6.919378992728976, '10.1.4.46': 4.782228804505263, '10.1.4.42': 4.511432742424385, '10.1.2.24': 3.459835014673997, '10.1.2.22': 3.2407604615497743, '9.66.11.13': 2.6668359169155993, '9.66.11.12': 2.586802299994103, '10.1.3.33': 2.540102432724444, '4.122.55.22': 2.485592505838196, '4.122.55.23': 2.485592505838196, '4.122.55.24': 2.485592505838196, '4.122.55.25': 2.485592505838196, '4.122.55.26': 2.485592505838196, '10.1.3.32': 2.4500702432780024, '4.122.55.21': 2.1949165482078326, '10.1.2.23': 2.179078344994263, '4.122.55.3': 2.0498843133284734, '10.1.3.34': 1.8763798579513147, '4.122.55.117': 1.7161183224335232, '4.122.55.2': 1.6384527379175453, '4.122.55.5': 1.534734013864855, '4.122.55.250': 1.5282546881515784, '4.122.55.112': 1.5106755032447645, '4.122.55.113': 1.5106755032447645, '4.122.55.114': 1.5106755032447645, '4.122.55.115': 1.5106755032447645, '4.122.55.111': 1.4290258692146443, '4.122.55.4': 1.3228118689628199, '4.122.55.6': 1.3228118689628199, '10.1.2.26': 1.2254699461426792, '10.1.2.28': 1.2254699461426792, '4.122.55.7': 1.2171037243126088, '10.1.2.29': 1.119255945890855, '10.1.2.25': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.44': 1.013547801240644, '10.1.4.45': 1.013547801240644, '9.66.11.14': 0.0}
# Elbow's x:  2 , y:  4.782228804505263 , value:  1.866354126142836

# First IP:  10.1.2.22
# {'10.1.4.47': 4.415580079596388, '10.1.4.43': 4.310418633997334, '10.1.3.33': 3.8612518229201345, '9.66.11.14': 3.2407604615497743, '10.1.4.42': 3.2281994373085494, '10.1.4.46': 3.1782831321068272, '10.1.2.24': 2.925119592595049, '4.122.55.22': 2.277961128875081, '4.122.55.23': 2.277961128875081, '4.122.55.24': 2.277961128875081, '4.122.55.25': 2.277961128875081, '4.122.55.26': 2.277961128875081, '10.1.2.23': 2.083792487172066, '10.1.3.32': 2.051377698871014, '4.122.55.21': 2.027270730436084, '9.66.11.13': 1.6760657713218778, '9.66.11.12': 1.5491447085900847, '4.122.55.2': 1.494420868877221, '10.1.2.29': 1.4372300135582208, '10.1.3.34': 1.270136972494808, '4.122.55.111': 1.1254624962725082, '4.122.55.5': 1.1254624962725082, '10.1.2.25': 1.013547801240644, '10.1.2.26': 1.013547801240644, '10.1.2.28': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.44': 1.013547801240644, '10.1.4.45': 1.013547801240644, '4.122.55.112': 1.013547801240644, '4.122.55.113': 1.013547801240644, '4.122.55.114': 1.013547801240644, '4.122.55.115': 1.013547801240644, '4.122.55.117': 1.013547801240644, '4.122.55.3': 1.013547801240644, '4.122.55.4': 1.013547801240644, '4.122.55.6': 1.013547801240644, '4.122.55.7': 1.013547801240644, '4.122.55.250': 1.013547801240644, '10.1.2.22': 0.0}
# Elbow's x:  7 , y:  2.277961128875081 , value:  0.6471584637199674

# First IP:  10.1.2.23
# {'10.1.2.24': 3.4852775369971383, '10.1.4.47': 2.4675903302213853, '9.66.11.14': 2.179078344994263, '10.1.2.22': 2.083792487172066, '10.1.4.43': 1.8331020887330696, '10.1.3.32': 1.6203091315038782, '10.1.4.42': 1.6203091315038782, '4.122.55.22': 1.3911592624114342, '4.122.55.23': 1.3911592624114342, '4.122.55.24': 1.3911592624114342, '4.122.55.25': 1.3911592624114342, '4.122.55.26': 1.3911592624114342, '10.1.3.33': 1.3750630696940478, '10.1.4.46': 1.3750630696940478, '9.66.11.13': 1.1404688639724372, '10.1.3.34': 1.1404688639724372, '4.122.55.21': 1.1404688639724372, '9.66.11.12': 1.013547801240644, '10.1.2.25': 1.013547801240644, '10.1.2.26': 1.013547801240644, '10.1.2.28': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.2.29': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.44': 1.013547801240644, '10.1.4.45': 1.013547801240644, '4.122.55.111': 1.013547801240644, '4.122.55.112': 1.013547801240644, '4.122.55.113': 1.013547801240644, '4.122.55.114': 1.013547801240644, '4.122.55.115': 1.013547801240644, '4.122.55.117': 1.013547801240644, '4.122.55.2': 1.013547801240644, '4.122.55.3': 1.013547801240644, '4.122.55.4': 1.013547801240644, '4.122.55.5': 1.013547801240644, '4.122.55.6': 1.013547801240644, '4.122.55.7': 1.013547801240644, '4.122.55.250': 1.013547801240644, '10.1.2.23': 0.0}
# Elbow's x:  1 , y:  2.4675903302213853 , value:  0.7291752215486307

# First IP:  10.1.2.24
# {'10.1.4.47': 3.8274192308486765, '10.1.2.23': 3.4852775369971383, '10.1.4.46': 3.4614141086225745, '9.66.11.14': 3.459835014673997, '10.1.2.22': 2.925119592595049, '10.1.4.43': 2.2877138402256763, '10.1.3.33': 1.8296748211866547, '10.1.4.42': 1.6409356553688998, '4.122.55.22': 1.56703754326955, '4.122.55.23': 1.56703754326955, '4.122.55.24': 1.56703754326955, '4.122.55.25': 1.56703754326955, '4.122.55.26': 1.56703754326955, '10.1.3.32': 1.5638022355118026, '10.1.3.34': 1.329208029790192, '9.66.11.13': 1.1404688639724372, '4.122.55.21': 1.1404688639724372, '9.66.11.12': 1.013547801240644, '10.1.2.25': 1.013547801240644, '10.1.2.26': 1.013547801240644, '10.1.2.28': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.2.29': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.44': 1.013547801240644, '10.1.4.45': 1.013547801240644, '4.122.55.111': 1.013547801240644, '4.122.55.112': 1.013547801240644, '4.122.55.113': 1.013547801240644, '4.122.55.114': 1.013547801240644, '4.122.55.115': 1.013547801240644, '4.122.55.117': 1.013547801240644, '4.122.55.2': 1.013547801240644, '4.122.55.3': 1.013547801240644, '4.122.55.4': 1.013547801240644, '4.122.55.5': 1.013547801240644, '4.122.55.6': 1.013547801240644, '4.122.55.7': 1.013547801240644, '4.122.55.250': 1.013547801240644, '10.1.2.24': 0.0}
# Elbow's x:  1 , y:  3.4852775369971383 , value:  0.3182782654769749

# First IP:  10.1.2.25
# {'10.1.2.29': 9.05518040943069, '10.1.2.27': 4.797597233185232, '10.1.2.26': 4.654271825137077, '10.1.4.44': 3.3508034424340716, '10.1.4.45': 3.0276552641160857, '10.1.4.48': 2.9496067179938184, '10.1.4.49': 2.8913782055868564, '4.122.55.3': 2.364749309406382, '4.122.55.22': 2.364749309406382, '4.122.55.23': 2.364749309406382, '4.122.55.24': 2.364749309406382, '4.122.55.25': 2.364749309406382, '4.122.55.26': 2.364749309406382, '10.1.2.28': 2.1293718538539954, '9.66.11.12': 1.5434379354683256, '9.66.11.13': 1.5434379354683256, '4.122.55.7': 1.417476413115229, '4.122.55.2': 1.4035009548422075, '4.122.55.4': 1.2433514880024112, '4.122.55.5': 1.2433514880024112, '4.122.55.6': 1.2433514880024112, '4.122.55.250': 1.2433514880024112, '10.1.3.34': 1.1476286593613254, '4.122.55.113': 1.1092706298817299, '4.122.55.114': 1.1092706298817299, '4.122.55.115': 1.1092706298817299, '4.122.55.117': 1.1092706298817299, '4.122.55.21': 1.1092706298817299, '9.66.11.14': 1.013547801240644, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.3.32': 1.013547801240644, '10.1.3.33': 1.013547801240644, '10.1.4.46': 1.013547801240644, '10.1.4.47': 1.013547801240644, '10.1.4.42': 1.013547801240644, '10.1.4.43': 1.013547801240644, '4.122.55.111': 1.013547801240644, '4.122.55.112': 1.013547801240644, '10.1.2.25': 0.0}
# Elbow's x:  1 , y:  4.797597233185232 , value:  4.114257768197303

# First IP:  10.1.2.26
# {'10.1.2.29': 6.008212451342451, '10.1.2.25': 4.654271825137077, '10.1.2.27': 3.538104344000742, '10.1.4.44': 3.504267712267089, '10.1.4.48': 3.1030709878268357, '10.1.4.49': 3.044842475419874, '10.1.4.45': 2.8288654140818768, '4.122.55.3': 2.730135724141435, '4.122.55.22': 2.730135724141435, '4.122.55.23': 2.730135724141435, '4.122.55.24': 2.730135724141435, '4.122.55.25': 2.730135724141435, '4.122.55.26': 2.730135724141435, '10.1.2.28': 2.4947582685890484, '4.122.55.2': 1.5614858036097887, '4.122.55.5': 1.4552736329044467, '9.66.11.12': 1.4546334385235433, '9.66.11.13': 1.4465848772467254, '4.122.55.7': 1.417476413115229, '10.1.3.34': 1.3595508042633608, '4.122.55.4': 1.2433514880024112, '4.122.55.6': 1.2433514880024112, '4.122.55.250': 1.2433514880024112, '9.66.11.14': 1.2254699461426792, '4.122.55.111': 1.2254699461426792, '4.122.55.21': 1.2192559829711564, '10.1.4.46': 1.1235331543300706, '10.1.4.47': 1.1235331543300706, '4.122.55.113': 1.1092706298817299, '4.122.55.114': 1.1092706298817299, '4.122.55.115': 1.1092706298817299, '4.122.55.117': 1.1092706298817299, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.3.32': 1.013547801240644, '10.1.3.33': 1.013547801240644, '10.1.4.42': 1.013547801240644, '10.1.4.43': 1.013547801240644, '4.122.55.112': 1.013547801240644, '10.1.2.26': 0.0}
# Elbow's x:  2 , y:  3.538104344000742 , value:  1.082330849402683

# First IP:  10.1.2.28
# {'4.122.55.3': 2.6935481186232573, '4.122.55.22': 2.6935481186232573, '4.122.55.23': 2.6935481186232573, '4.122.55.24': 2.6935481186232573, '4.122.55.25': 2.6935481186232573, '4.122.55.26': 2.6935481186232573, '10.1.2.26': 2.4947582685890484, '10.1.2.29': 2.3475451156005405, '10.1.4.44': 2.321476506881426, '10.1.2.25': 2.1293718538539954, '10.1.4.45': 1.9552469287411776, '10.1.4.48': 1.954544924743643, '10.1.4.49': 1.954544924743643, '10.1.2.27': 1.7965600759760618, '4.122.55.2': 1.5614858036097887, '4.122.55.5': 1.4552736329044467, '9.66.11.12': 1.4180458330053654, '4.122.55.7': 1.417476413115229, '9.66.11.13': 1.4099972717285474, '10.1.3.34': 1.3595508042633608, '4.122.55.4': 1.2433514880024112, '4.122.55.6': 1.2433514880024112, '4.122.55.250': 1.2433514880024112, '9.66.11.14': 1.2254699461426795, '4.122.55.111': 1.2254699461426795, '4.122.55.21': 1.2192559829711564, '10.1.4.46': 1.1235331543300706, '10.1.4.47': 1.1235331543300706, '4.122.55.113': 1.1092706298817299, '4.122.55.114': 1.1092706298817299, '4.122.55.115': 1.1092706298817299, '4.122.55.117': 1.1092706298817299, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.3.32': 1.013547801240644, '10.1.3.33': 1.013547801240644, '10.1.4.42': 1.013547801240644, '10.1.4.43': 1.013547801240644, '4.122.55.112': 1.013547801240644, '10.1.2.28': 0.0}
# Elbow's x:  10 , y:  1.9552469287411776 , value:  0.17342292111528312

# First IP:  10.1.2.27
# {'10.1.2.29': 4.981683804969308, '10.1.2.25': 4.797597233185232, '10.1.2.26': 3.538104344000742, '10.1.4.44': 3.017991664556138, '10.1.4.49': 2.8712134549657993, '10.1.4.48': 2.6545343896302676, '10.1.4.45': 2.4602651185306224, '4.122.55.3': 2.162661738263283, '4.122.55.22': 2.162661738263283, '4.122.55.23': 2.162661738263283, '4.122.55.24': 2.162661738263283, '4.122.55.25': 2.162661738263283, '4.122.55.26': 2.162661738263283, '10.1.2.28': 1.7965600759760618, '9.66.11.12': 1.5434379354683256, '9.66.11.13': 1.5434379354683256, '4.122.55.2': 1.5342251615770417, '4.122.55.4': 1.3740756947372454, '4.122.55.7': 1.3740756947372454, '4.122.55.250': 1.3740756947372454, '4.122.55.5': 1.2433514880024112, '4.122.55.6': 1.2433514880024112, '4.122.55.113': 1.239994836616564, '4.122.55.115': 1.239994836616564, '4.122.55.117': 1.239994836616564, '4.122.55.21': 1.239994836616564, '10.1.3.34': 1.1476286593613254, '4.122.55.114': 1.1092706298817299, '9.66.11.14': 1.013547801240644, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.3.32': 1.013547801240644, '10.1.3.33': 1.013547801240644, '10.1.4.46': 1.013547801240644, '10.1.4.47': 1.013547801240644, '10.1.4.42': 1.013547801240644, '10.1.4.43': 1.013547801240644, '4.122.55.111': 1.013547801240644, '4.122.55.112': 1.013547801240644, '10.1.2.27': 0.0}
# Elbow's x:  2 , y:  3.538104344000742 , value:  0.7393802097398856

# First IP:  10.1.2.29
# {'10.1.2.25': 9.05518040943069, '10.1.2.26': 6.008212451342451, '10.1.2.27': 4.981683804969308, '4.122.55.22': 3.646979094855297, '4.122.55.23': 3.646979094855297, '4.122.55.24': 3.646979094855297, '4.122.55.25': 3.646979094855297, '4.122.55.26': 3.646979094855297, '10.1.4.44': 3.3631861999352384, '4.122.55.3': 3.352964991060091, '10.1.4.48': 3.1677799797403634, '10.1.4.49': 3.1095514673334015, '10.1.4.45': 2.994711578180161, '10.1.2.28': 2.3475451156005405, '4.122.55.2': 2.197447365396271, '4.122.55.21': 2.1733271535840997, '9.66.11.12': 2.072828292436113, '9.66.11.13': 2.072828292436113, '4.122.55.113': 1.8793130497888935, '4.122.55.115': 1.8793130497888935, '4.122.55.117': 1.8793130497888935, '4.122.55.4': 1.8793130497888935, '4.122.55.250': 1.8793130497888935, '4.122.55.7': 1.802518851502183, '4.122.55.5': 1.7485888430540593, '4.122.55.6': 1.7485888430540593, '10.1.3.34': 1.4961720336277757, '10.1.2.22': 1.4372300135582208, '10.1.4.46': 1.4372300135582208, '10.1.4.47': 1.4372300135582208, '4.122.55.114': 1.3573707414238891, '4.122.55.112': 1.2644669246401725, '9.66.11.14': 1.119255945890855, '10.1.3.32': 1.1146849734254007, '10.1.3.33': 1.1146849734254007, '10.1.4.42': 1.1146849734254007, '10.1.4.43': 1.1146849734254007, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.111': 1.013547801240644, '10.1.2.29': 0.0}
# Elbow's x:  1 , y:  6.008212451342451 , value:  2.020439311715096

# First IP:  10.1.3.32
# {'10.1.4.47': 7.116217373516253, '10.1.4.43': 6.936811145854096, '10.1.4.42': 4.941977795996864, '10.1.3.33': 4.587899886474319, '10.1.4.46': 3.981496424290855, '9.66.11.14': 2.4500702432780024, '4.122.55.22': 2.2369596442427273, '4.122.55.23': 2.2369596442427273, '4.122.55.24': 2.2369596442427273, '4.122.55.25': 2.2369596442427273, '4.122.55.26': 2.2369596442427273, '10.1.2.22': 2.051377698871014, '4.122.55.21': 2.0482204784249727, '4.122.55.2': 1.7896056555060569, '10.1.3.34': 1.6644577130492795, '10.1.2.23': 1.6203091315038782, '10.1.2.24': 1.5638022355118026, '9.66.11.13': 1.4757185472315246, '4.122.55.117': 1.4739647865513315, '4.122.55.111': 1.3728276143665745, '4.122.55.113': 1.3182408964973658, '4.122.55.115': 1.3182408964973658, '4.122.55.3': 1.3182408964973658, '4.122.55.4': 1.3182408964973658, '4.122.55.5': 1.3182408964973658, '4.122.55.6': 1.3182408964973658, '4.122.55.7': 1.3182408964973658, '4.122.55.250': 1.3182408964973658, '4.122.55.112': 1.2171037243126088, '4.122.55.114': 1.2171037243126088, '10.1.2.29': 1.1146849734254007, '10.1.4.44': 1.1146849734254007, '10.1.4.45': 1.1146849734254007, '9.66.11.12': 1.013547801240644, '10.1.2.25': 1.013547801240644, '10.1.2.26': 1.013547801240644, '10.1.2.28': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.3.32': 0.0}
# Elbow's x:  2 , y:  4.941977795996864 , value:  1.6407554403346882

# First IP:  10.1.3.33
# {'10.1.4.43': 4.976421389175525, '10.1.4.46': 4.694651763712206, '10.1.3.32': 4.587899886474319, '10.1.4.47': 4.471131235561043, '10.1.4.42': 4.101733484447008, '10.1.2.22': 3.8612518229201345, '9.66.11.14': 2.540102432724444, '4.122.55.22': 2.3382661417280324, '4.122.55.23': 2.3382661417280324, '4.122.55.24': 2.3382661417280324, '4.122.55.25': 2.3382661417280324, '4.122.55.26': 2.3382661417280324, '4.122.55.21': 2.1495269759102773, '10.1.2.24': 1.8296748211866547, '4.122.55.2': 1.7789974579594978, '10.1.3.34': 1.6644577130492795, '9.66.11.13': 1.5876332422633888, '4.122.55.111': 1.4847423093984387, '4.122.55.117': 1.4739647865513315, '4.122.55.5': 1.4301555915292297, '10.1.2.23': 1.3750630696940478, '4.122.55.113': 1.3182408964973658, '4.122.55.115': 1.3182408964973658, '4.122.55.3': 1.3182408964973658, '4.122.55.4': 1.3182408964973658, '4.122.55.6': 1.3182408964973658, '4.122.55.7': 1.3182408964973658, '4.122.55.250': 1.3182408964973658, '4.122.55.112': 1.2171037243126088, '4.122.55.114': 1.2171037243126088, '9.66.11.12': 1.1254624962725082, '10.1.2.29': 1.1146849734254007, '10.1.4.44': 1.1146849734254007, '10.1.4.45': 1.1146849734254007, '10.1.2.25': 1.013547801240644, '10.1.2.26': 1.013547801240644, '10.1.2.28': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.3.33': 0.0}
# Elbow's x:  6 , y:  2.540102432724444 , value:  1.119313099199279

# First IP:  10.1.3.34
# {'10.1.4.46': 2.1417888752074465, '4.122.55.22': 2.010460716071996, '4.122.55.23': 2.010460716071996, '4.122.55.24': 2.010460716071996, '4.122.55.25': 2.010460716071996, '4.122.55.26': 2.010460716071996, '9.66.11.14': 1.8763798579513147, '10.1.4.47': 1.7771901119292834, '9.66.11.13': 1.7073234475665038, '10.1.3.32': 1.6644577130492795, '10.1.3.33': 1.6644577130492795, '10.1.4.43': 1.6644577130492795, '4.122.55.21': 1.5857039003209512, '4.122.55.3': 1.5631067273353256, '4.122.55.5': 1.5631067273353256, '10.1.2.29': 1.4961720336277757, '10.1.4.42': 1.4757185472315246, '4.122.55.111': 1.4290258692146443, '10.1.2.26': 1.3595508042633608, '10.1.2.28': 1.3595508042633608, '4.122.55.2': 1.3511845824332904, '4.122.55.4': 1.3511845824332904, '4.122.55.6': 1.3511845824332904, '4.122.55.7': 1.3511845824332904, '4.122.55.250': 1.3511845824332904, '10.1.2.24': 1.329208029790192, '10.1.2.22': 1.270136972494808, '9.66.11.12': 1.2532012628524414, '4.122.55.112': 1.2171037243126088, '4.122.55.113': 1.2171037243126088, '4.122.55.114': 1.2171037243126088, '4.122.55.115': 1.2171037243126088, '4.122.55.117': 1.2171037243126088, '10.1.2.25': 1.1476286593613254, '10.1.2.27': 1.1476286593613254, '10.1.4.48': 1.1476286593613254, '10.1.4.49': 1.1476286593613254, '10.1.4.44': 1.1476286593613254, '10.1.4.45': 1.1476286593613254, '10.1.2.23': 1.1404688639724372, '10.1.3.34': 0.0}
# Elbow's x:  1 , y:  2.010460716071996 , value:  0.13132815913545048

# First IP:  10.1.4.46
# {'10.1.4.43': 42.568166834420055, '10.1.4.47': 41.5250685692135, '10.1.4.42': 18.71499386544565, '9.66.11.14': 4.782228804505263, '10.1.3.33': 4.694651763712205, '10.1.3.32': 3.981496424290855, '10.1.2.24': 3.4614141086225745, '10.1.2.22': 3.1782831321068272, '4.122.55.21': 2.4965358966514413, '4.122.55.22': 2.4965358966514413, '4.122.55.23': 2.4965358966514413, '4.122.55.24': 2.4965358966514413, '4.122.55.25': 2.4965358966514413, '4.122.55.26': 2.4965358966514413, '9.66.11.13': 2.1545292721363363, '10.1.3.34': 2.1417888752074465, '4.122.55.2': 1.8537006820031514, '9.66.11.12': 1.6591300616795115, '4.122.55.111': 1.5947276624878652, '4.122.55.5': 1.4390037724338995, '10.1.2.29': 1.4372300135582208, '10.1.2.23': 1.3750630696940478, '4.122.55.117': 1.3728276143665745, '4.122.55.3': 1.3270890774020354, '4.122.55.112': 1.2171037243126088, '4.122.55.113': 1.2171037243126088, '4.122.55.114': 1.2171037243126088, '4.122.55.115': 1.2171037243126088, '4.122.55.4': 1.2171037243126088, '4.122.55.6': 1.2171037243126088, '4.122.55.7': 1.2171037243126088, '4.122.55.250': 1.2171037243126088, '10.1.2.26': 1.1235331543300706, '10.1.2.28': 1.1235331543300706, '10.1.2.25': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.44': 1.013547801240644, '10.1.4.45': 1.013547801240644, '10.1.4.46': 0.0}
# Elbow's x:  3 , y:  4.782228804505263 , value:  13.845188020147328

# First IP:  10.1.4.47
# {'10.1.4.46': 41.5250685692135, '10.1.4.43': 24.46168299793246, '10.1.4.42': 22.1513186996019, '9.66.11.14': 9.147005199398548, '10.1.3.32': 7.116217373516253, '10.1.3.33': 4.471131235561043, '10.1.2.22': 4.415580079596388, '10.1.2.24': 3.827419230848677, '4.122.55.22': 3.17856767184288, '4.122.55.23': 3.17856767184288, '4.122.55.24': 3.17856767184288, '4.122.55.25': 3.17856767184288, '4.122.55.26': 3.17856767184288, '4.122.55.21': 2.5013085941067708, '10.1.2.23': 2.4675903302213853, '9.66.11.13': 2.1593019695916658, '4.122.55.2': 1.8537006820031514, '10.1.3.34': 1.7771901119292834, '9.66.11.12': 1.6591300616795115, '4.122.55.111': 1.5947276624878652, '4.122.55.5': 1.4390037724338995, '10.1.2.29': 1.4372300135582208, '4.122.55.117': 1.3728276143665745, '4.122.55.3': 1.3270890774020354, '4.122.55.112': 1.2171037243126088, '4.122.55.113': 1.2171037243126088, '4.122.55.114': 1.2171037243126088, '4.122.55.115': 1.2171037243126088, '4.122.55.4': 1.2171037243126088, '4.122.55.6': 1.2171037243126088, '4.122.55.7': 1.2171037243126088, '4.122.55.250': 1.2171037243126088, '10.1.2.26': 1.1235331543300706, '10.1.2.28': 1.1235331543300706, '10.1.2.25': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.44': 1.013547801240644, '10.1.4.45': 1.013547801240644, '10.1.4.47': 0.0}
# Elbow's x:  1 , y:  24.46168299793246 , value:  14.753021272950484

# First IP:  10.1.4.48
# {'10.1.4.44': 4.095064812447016, '10.1.4.45': 3.9007151158047564, '10.1.2.29': 3.1677799797403634, '10.1.2.26': 3.1030709878268357, '10.1.4.49': 3.0269532601185514, '10.1.2.25': 2.9496067179938184, '10.1.2.27': 2.6545343896302676, '4.122.55.3': 2.18992238029603, '4.122.55.22': 2.18992238029603, '4.122.55.23': 2.18992238029603, '4.122.55.24': 2.18992238029603, '4.122.55.25': 2.18992238029603, '4.122.55.26': 2.18992238029603, '10.1.2.28': 1.954544924743643, '4.122.55.2': 1.5614858036097887, '9.66.11.12': 1.5434379354683256, '9.66.11.13': 1.5434379354683256, '4.122.55.4': 1.2433514880024112, '4.122.55.5': 1.2433514880024112, '4.122.55.6': 1.2433514880024112, '4.122.55.7': 1.2433514880024112, '4.122.55.250': 1.2433514880024112, '10.1.3.34': 1.1476286593613254, '4.122.55.113': 1.1092706298817299, '4.122.55.114': 1.1092706298817299, '4.122.55.115': 1.1092706298817299, '4.122.55.117': 1.1092706298817299, '4.122.55.21': 1.1092706298817299, '9.66.11.14': 1.013547801240644, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.3.32': 1.013547801240644, '10.1.3.33': 1.013547801240644, '10.1.4.46': 1.013547801240644, '10.1.4.47': 1.013547801240644, '10.1.4.42': 1.013547801240644, '10.1.4.43': 1.013547801240644, '4.122.55.111': 1.013547801240644, '4.122.55.112': 1.013547801240644, '10.1.4.48': 0.0}
# Elbow's x:  2 , y:  3.1677799797403634 , value:  0.6682261441508652

# First IP:  10.1.4.49
# {'10.1.4.44': 4.311743877782548, '10.1.4.45': 4.1173941811402885, '10.1.2.29': 3.1095514673334015, '10.1.2.26': 3.044842475419874, '10.1.4.48': 3.0269532601185514, '10.1.2.25': 2.8913782055868564, '10.1.2.27': 2.8712134549657993, '4.122.55.3': 2.18992238029603, '4.122.55.22': 2.18992238029603, '4.122.55.23': 2.18992238029603, '4.122.55.24': 2.18992238029603, '4.122.55.25': 2.18992238029603, '4.122.55.26': 2.18992238029603, '10.1.2.28': 1.954544924743643, '4.122.55.2': 1.5614858036097887, '9.66.11.12': 1.5434379354683256, '9.66.11.13': 1.5434379354683256, '4.122.55.4': 1.2433514880024112, '4.122.55.5': 1.2433514880024112, '4.122.55.6': 1.2433514880024112, '4.122.55.7': 1.2433514880024112, '4.122.55.250': 1.2433514880024112, '10.1.3.34': 1.1476286593613254, '4.122.55.113': 1.1092706298817299, '4.122.55.114': 1.1092706298817299, '4.122.55.115': 1.1092706298817299, '4.122.55.117': 1.1092706298817299, '4.122.55.21': 1.1092706298817299, '9.66.11.14': 1.013547801240644, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.3.32': 1.013547801240644, '10.1.3.33': 1.013547801240644, '10.1.4.46': 1.013547801240644, '10.1.4.47': 1.013547801240644, '10.1.4.42': 1.013547801240644, '10.1.4.43': 1.013547801240644, '4.122.55.111': 1.013547801240644, '4.122.55.112': 1.013547801240644, '10.1.4.49': 0.0}
# Elbow's x:  2 , y:  3.1095514673334015 , value:  0.9431337218933598

# First IP:  10.1.4.42
# {'10.1.4.47': 22.1513186996019, '10.1.4.46': 18.71499386544565, '10.1.4.43': 17.245466624235068, '10.1.3.32': 4.941977795996864, '9.66.11.14': 4.511432742424385, '10.1.3.33': 4.101733484447008, '10.1.2.22': 3.2281994373085494, '4.122.55.21': 2.4190472092458153, '4.122.55.22': 2.4190472092458153, '4.122.55.23': 2.4190472092458153, '4.122.55.24': 2.4190472092458153, '4.122.55.25': 2.4190472092458153, '4.122.55.26': 2.4190472092458153, '4.122.55.2': 1.9725687520449549, '9.66.11.13': 1.8188773498720687, '4.122.55.113': 1.6795593186903226, '4.122.55.115': 1.6795593186903226, '10.1.2.24': 1.6409356553688998, '10.1.2.23': 1.6203091315038782, '4.122.55.112': 1.578422146505566, '4.122.55.114': 1.578422146505566, '4.122.55.117': 1.5061045307793104, '4.122.55.3': 1.491695684408378, '4.122.55.4': 1.491695684408378, '4.122.55.5': 1.491695684408378, '4.122.55.6': 1.491695684408378, '4.122.55.7': 1.491695684408378, '4.122.55.250': 1.491695684408378, '10.1.3.34': 1.4757185472315246, '4.122.55.111': 1.390558512223621, '9.66.11.12': 1.3567066038811884, '10.1.2.29': 1.1146849734254007, '10.1.4.44': 1.1146849734254007, '10.1.4.45': 1.1146849734254007, '10.1.2.25': 1.013547801240644, '10.1.2.26': 1.013547801240644, '10.1.2.28': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.42': 0.0}
# Elbow's x:  3 , y:  4.941977795996864 , value:  11.872943774665726

# First IP:  10.1.4.43
# {'10.1.4.46': 42.568166834420055, '10.1.4.47': 24.46168299793246, '10.1.4.42': 17.245466624235068, '10.1.3.32': 6.936811145854096, '9.66.11.14': 6.919378992728976, '10.1.3.33': 4.976421389175525, '10.1.2.22': 4.310418633997334, '4.122.55.22': 2.3743060652301278, '4.122.55.23': 2.3743060652301278, '4.122.55.24': 2.3743060652301278, '4.122.55.25': 2.3743060652301278, '4.122.55.26': 2.3743060652301278, '10.1.2.24': 2.2877138402256763, '4.122.55.21': 2.185566899412373, '9.66.11.13': 1.8625408200058822, '10.1.2.23': 1.8331020887330696, '4.122.55.2': 1.8150373814615932, '10.1.3.34': 1.6644577130492795, '4.122.55.111': 1.4847423093984387, '4.122.55.117': 1.4739647865513315, '4.122.55.5': 1.4301555915292297, '4.122.55.113': 1.3182408964973658, '4.122.55.115': 1.3182408964973658, '4.122.55.3': 1.3182408964973658, '4.122.55.4': 1.3182408964973658, '4.122.55.6': 1.3182408964973658, '4.122.55.7': 1.3182408964973658, '4.122.55.250': 1.3182408964973658, '4.122.55.112': 1.2171037243126088, '4.122.55.114': 1.2171037243126088, '9.66.11.12': 1.1254624962725082, '10.1.2.29': 1.1146849734254007, '10.1.4.44': 1.1146849734254007, '10.1.4.45': 1.1146849734254007, '10.1.2.25': 1.013547801240644, '10.1.2.26': 1.013547801240644, '10.1.2.28': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.43': 0.0}
# Elbow's x:  1 , y:  24.46168299793246 , value:  10.890267462790199

# First IP:  10.1.4.44
# {'10.1.4.49': 4.311743877782548, '10.1.4.48': 4.095064812447016, '10.1.2.26': 3.5042677122670893, '10.1.2.29': 3.3631861999352384, '10.1.2.25': 3.3508034424340716, '10.1.2.27': 3.017991664556138, '10.1.4.45': 2.754208947740344, '4.122.55.3': 2.657991134618569, '4.122.55.22': 2.657991134618569, '4.122.55.23': 2.657991134618569, '4.122.55.24': 2.657991134618569, '4.122.55.25': 2.657991134618569, '4.122.55.26': 2.657991134618569, '10.1.2.28': 2.321476506881426, '9.66.11.12': 1.5434379354683256, '9.66.11.13': 1.5434379354683256, '4.122.55.7': 1.5186135852999858, '4.122.55.2': 1.5024735089547492, '4.122.55.4': 1.3444886601871682, '4.122.55.5': 1.3444886601871682, '4.122.55.6': 1.3444886601871682, '4.122.55.250': 1.3444886601871682, '4.122.55.113': 1.2104078020664866, '4.122.55.115': 1.2104078020664866, '4.122.55.117': 1.2104078020664866, '4.122.55.21': 1.2104078020664866, '10.1.3.34': 1.1476286593613254, '10.1.3.32': 1.1146849734254007, '10.1.3.33': 1.1146849734254007, '10.1.4.42': 1.1146849734254007, '10.1.4.43': 1.1146849734254007, '4.122.55.114': 1.1092706298817299, '9.66.11.14': 1.013547801240644, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.4.46': 1.013547801240644, '10.1.4.47': 1.013547801240644, '4.122.55.111': 1.013547801240644, '4.122.55.112': 1.013547801240644, '10.1.4.44': 0.0}
# Elbow's x:  14 , y:  1.5434379354683256 , value:  0.7780385714131

# First IP:  10.1.4.45
# {'10.1.4.49': 4.1173941811402885, '10.1.4.48': 3.9007151158047564, '10.1.2.25': 3.0276552641160857, '10.1.2.29': 2.994711578180161, '10.1.2.26': 2.8288654140818768, '10.1.4.44': 2.754208947740344, '10.1.2.27': 2.4602651185306224, '4.122.55.3': 2.2917615564783214, '4.122.55.22': 2.2917615564783214, '4.122.55.23': 2.2917615564783214, '4.122.55.24': 2.2917615564783214, '4.122.55.25': 2.2917615564783214, '4.122.55.26': 2.2917615564783214, '10.1.2.28': 1.9552469287411776, '9.66.11.12': 1.5434379354683256, '9.66.11.13': 1.5434379354683256, '4.122.55.2': 1.5046381270269642, '4.122.55.4': 1.3444886601871682, '4.122.55.5': 1.3444886601871682, '4.122.55.6': 1.3444886601871682, '4.122.55.7': 1.3444886601871682, '4.122.55.250': 1.3444886601871682, '4.122.55.113': 1.2104078020664866, '4.122.55.115': 1.2104078020664866, '4.122.55.117': 1.2104078020664866, '4.122.55.21': 1.2104078020664866, '10.1.3.34': 1.1476286593613254, '10.1.3.32': 1.1146849734254007, '10.1.3.33': 1.1146849734254007, '10.1.4.42': 1.1146849734254007, '10.1.4.43': 1.1146849734254007, '4.122.55.114': 1.1092706298817299, '9.66.11.14': 1.013547801240644, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.4.46': 1.013547801240644, '10.1.4.47': 1.013547801240644, '4.122.55.111': 1.013547801240644, '4.122.55.112': 1.013547801240644, '10.1.4.45': 0.0}
# Elbow's x:  2 , y:  3.0276552641160857 , value:  0.8401161657527467

# First IP:  4.122.55.111
# {'4.122.55.114': 3.408003551292032, '4.122.55.5': 2.9355895767401483, '4.122.55.22': 2.776655486349989, '4.122.55.24': 2.776655486349989, '4.122.55.25': 2.776655486349989, '4.122.55.112': 2.757834812746949, '4.122.55.21': 2.6747186945373804, '4.122.55.23': 2.6251060991075854, '4.122.55.26': 2.6251060991075854, '4.122.55.6': 2.501653732171224, '4.122.55.117': 2.4960429238406094, '4.122.55.3': 2.2873296599401285, '4.122.55.115': 2.1845616127048864, '4.122.55.2': 2.1210324004570342, '4.122.55.4': 2.0754075150380933, '4.122.55.113': 1.9864272890823182, '4.122.55.7': 1.9653085104030685, '4.122.55.250': 1.9653085104030685, '10.1.4.46': 1.5947276624878652, '10.1.4.47': 1.5947276624878652, '10.1.3.33': 1.4847423093984387, '10.1.4.43': 1.4847423093984387, '9.66.11.13': 1.4309552111570816, '9.66.11.14': 1.4290258692146443, '10.1.3.34': 1.4290258692146443, '10.1.4.42': 1.390558512223621, '10.1.3.32': 1.3728276143665745, '9.66.11.12': 1.2354478493619347, '10.1.2.26': 1.2254699461426795, '10.1.2.28': 1.2254699461426795, '10.1.2.22': 1.1254624962725082, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.2.25': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.2.29': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.44': 1.013547801240644, '10.1.4.45': 1.013547801240644, '4.122.55.111': 0.0}
# Elbow's x:  18 , y:  1.5947276624878652 , value:  0.3705808479152033

# First IP:  4.122.55.112
# {'4.122.55.111': 2.757834812746949, '4.122.55.5': 2.530885614246722, '4.122.55.6': 2.530885614246722, '4.122.55.3': 2.5074343100225596, '4.122.55.117': 2.447315545509061, '4.122.55.21': 2.404091268084542, '4.122.55.22': 2.404091268084542, '4.122.55.24': 2.404091268084542, '4.122.55.25': 2.404091268084542, '4.122.55.2': 2.3745264988136503, '4.122.55.115': 2.291558124427304, '4.122.55.114': 2.2588802893352242, '4.122.55.23': 2.252541880842138, '4.122.55.26': 2.252541880842138, '4.122.55.4': 2.216227633802597, '4.122.55.250': 2.216227633802597, '4.122.55.113': 2.093423800804736, '4.122.55.7': 1.9653085104030685, '10.1.4.42': 1.578422146505566, '9.66.11.13': 1.5106755032447645, '9.66.11.14': 1.5106755032447645, '9.66.11.12': 1.3071195801727997, '10.1.2.29': 1.2644669246401725, '10.1.3.32': 1.2171037243126088, '10.1.3.33': 1.2171037243126088, '10.1.3.34': 1.2171037243126088, '10.1.4.46': 1.2171037243126088, '10.1.4.47': 1.2171037243126088, '10.1.4.43': 1.2171037243126088, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '10.1.2.25': 1.013547801240644, '10.1.2.26': 1.013547801240644, '10.1.2.28': 1.013547801240644, '10.1.2.27': 1.013547801240644, '10.1.4.48': 1.013547801240644, '10.1.4.49': 1.013547801240644, '10.1.4.44': 1.013547801240644, '10.1.4.45': 1.013547801240644, '4.122.55.112': 0.0}
# Elbow's x:  18 , y:  1.578422146505566 , value:  0.31913972063670126

# First IP:  4.122.55.113
# {'4.122.55.21': 3.040056171912512, '4.122.55.22': 3.040056171912512, '4.122.55.24': 3.040056171912512, '4.122.55.25': 3.040056171912512, '4.122.55.115': 2.927523028255275, '4.122.55.5': 2.9207795179382368, '4.122.55.23': 2.8885067846701085, '4.122.55.26': 2.8885067846701085, '4.122.55.117': 2.8666013840015, '4.122.55.3': 2.6305052963065365, '4.122.55.4': 2.6305052963065365, '4.122.55.6': 2.611369326260709, '4.122.55.2': 2.520406291671512, '4.122.55.250': 2.520406291671512, '4.122.55.7': 2.2694871682719837, '4.122.55.114': 2.1863276175884523, '4.122.55.112': 2.093423800804736, '4.122.55.111': 1.9864272890823182, '10.1.2.29': 1.8793130497888935, '10.1.4.42': 1.6795593186903226, '9.66.11.13': 1.6063983318858504, '9.66.11.14': 1.5106755032447645, '9.66.11.12': 1.4028424088138856, '10.1.3.32': 1.3182408964973658, '10.1.3.33': 1.3182408964973658, '10.1.4.43': 1.3182408964973658, '10.1.2.27': 1.239994836616564, '10.1.3.34': 1.2171037243126088, '10.1.4.46': 1.2171037243126088, '10.1.4.47': 1.2171037243126088, '10.1.4.44': 1.2104078020664866, '10.1.4.45': 1.2104078020664866, '10.1.2.25': 1.1092706298817299, '10.1.2.26': 1.1092706298817299, '10.1.2.28': 1.1092706298817299, '10.1.4.48': 1.1092706298817299, '10.1.4.49': 1.1092706298817299, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.113': 0.0}
# Elbow's x:  9 , y:  2.6305052963065365 , value:  0.23609608769496315

# First IP:  4.122.55.114
# {'4.122.55.111': 3.408003551292032, '4.122.55.3': 2.532883091148787, '4.122.55.5': 2.532883091148787, '4.122.55.21': 2.4969950848682583, '4.122.55.22': 2.4969950848682583, '4.122.55.24': 2.4969950848682583, '4.122.55.25': 2.4969950848682583, '4.122.55.2': 2.4611244309082307, '4.122.55.115': 2.3844619412110206, '4.122.55.23': 2.3454456976258546, '4.122.55.26': 2.3454456976258546, '4.122.55.117': 2.3235402969572463, '4.122.55.7': 2.317250671586599, '4.122.55.4': 2.309131450586314, '4.122.55.6': 2.309131450586314, '4.122.55.250': 2.309131450586314, '4.122.55.112': 2.2588802893352242, '4.122.55.113': 2.1863276175884523, '9.66.11.13': 1.6063983318858504, '10.1.4.42': 1.578422146505566, '9.66.11.14': 1.5106755032447645, '9.66.11.12': 1.4028424088138856, '10.1.2.29': 1.3573707414238891, '10.1.3.32': 1.2171037243126088, '10.1.3.33': 1.2171037243126088, '10.1.3.34': 1.2171037243126088, '10.1.4.46': 1.2171037243126088, '10.1.4.47': 1.2171037243126088, '10.1.4.43': 1.2171037243126088, '10.1.2.25': 1.1092706298817299, '10.1.2.26': 1.1092706298817299, '10.1.2.28': 1.1092706298817299, '10.1.2.27': 1.1092706298817299, '10.1.4.48': 1.1092706298817299, '10.1.4.49': 1.1092706298817299, '10.1.4.44': 1.1092706298817299, '10.1.4.45': 1.1092706298817299, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.114': 0.0}
# Elbow's x:  1 , y:  2.532883091148787 , value:  0.8751204601432452

# First IP:  4.122.55.115
# {'4.122.55.21': 3.238190495535081, '4.122.55.22': 3.238190495535081, '4.122.55.24': 3.238190495535081, '4.122.55.25': 3.238190495535081, '4.122.55.3': 3.086957386736434, '4.122.55.23': 3.086641108292677, '4.122.55.26': 3.086641108292677, '4.122.55.117': 3.0647357076240684, '4.122.55.113': 2.927523028255275, '4.122.55.5': 2.919602654518302, '4.122.55.4': 2.828639619929105, '4.122.55.6': 2.8095036498832773, '4.122.55.2': 2.7185406152940805, '4.122.55.250': 2.7185406152940805, '4.122.55.7': 2.467621491894552, '4.122.55.114': 2.3844619412110206, '4.122.55.112': 2.291558124427304, '4.122.55.111': 2.1845616127048864, '10.1.2.29': 1.8793130497888935, '10.1.4.42': 1.6795593186903226, '9.66.11.13': 1.6063983318858504, '9.66.11.14': 1.5106755032447645, '9.66.11.12': 1.4028424088138856, '10.1.3.32': 1.3182408964973658, '10.1.3.33': 1.3182408964973658, '10.1.4.43': 1.3182408964973658, '10.1.2.27': 1.239994836616564, '10.1.3.34': 1.2171037243126088, '10.1.4.46': 1.2171037243126088, '10.1.4.47': 1.2171037243126088, '10.1.4.44': 1.2104078020664866, '10.1.4.45': 1.2104078020664866, '10.1.2.25': 1.1092706298817299, '10.1.2.26': 1.1092706298817299, '10.1.2.28': 1.1092706298817299, '10.1.4.48': 1.1092706298817299, '10.1.4.49': 1.1092706298817299, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.115': 0.0}
# Elbow's x:  14 , y:  2.467621491894552 , value:  0.1677595727159975

# First IP:  4.122.55.117
# {'4.122.55.21': 3.332992741335272, '4.122.55.22': 3.332992741335272, '4.122.55.24': 3.332992741335272, '4.122.55.25': 3.332992741335272, '4.122.55.23': 3.1814433540928677, '4.122.55.26': 3.1814433540928677, '4.122.55.115': 3.0647357076240684, '4.122.55.113': 2.8666013840015, '4.122.55.250': 2.8630617902290645, '4.122.55.5': 2.8586810102645273, '4.122.55.2': 2.8133428610942715, '4.122.55.3': 2.7677179756753305, '4.122.55.4': 2.7677179756753305, '4.122.55.6': 2.7485820056295025, '4.122.55.111': 2.4960429238406094, '4.122.55.112': 2.447315545509061, '4.122.55.7': 2.4066998476407773, '4.122.55.114': 2.3235402969572463, '10.1.2.29': 1.8793130497888935, '9.66.11.14': 1.7161183224335232, '9.66.11.12': 1.6082852280026443, '9.66.11.13': 1.6063983318858504, '10.1.4.42': 1.5061045307793104, '10.1.3.32': 1.4739647865513315, '10.1.3.33': 1.4739647865513315, '10.1.4.43': 1.4739647865513315, '10.1.4.46': 1.3728276143665745, '10.1.4.47': 1.3728276143665745, '10.1.2.27': 1.239994836616564, '10.1.3.34': 1.2171037243126088, '10.1.4.44': 1.2104078020664866, '10.1.4.45': 1.2104078020664866, '10.1.2.25': 1.1092706298817299, '10.1.2.26': 1.1092706298817299, '10.1.2.28': 1.1092706298817299, '10.1.4.48': 1.1092706298817299, '10.1.4.49': 1.1092706298817299, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.117': 0.0}
# Elbow's x:  18 , y:  1.8793130497888935 , value:  0.28103251981298216

# First IP:  4.122.55.2
# {'4.122.55.3': 5.479203093862012, '4.122.55.22': 3.8187487181851627, '4.122.55.24': 3.8187487181851627, '4.122.55.25': 3.8187487181851627, '4.122.55.23': 3.6671993309427586, '4.122.55.26': 3.6671993309427586, '4.122.55.4': 3.5909731782506418, '4.122.55.250': 3.5909731782506418, '4.122.55.5': 3.460248971515808, '4.122.55.6': 3.460248971515808, '4.122.55.21': 3.366533544457104, '4.122.55.7': 3.3400540548511137, '4.122.55.117': 2.7122056889095147, '4.122.55.115': 2.617403443109324, '4.122.55.114': 2.4611244309082307, '4.122.55.113': 2.4192691194867555, '4.122.55.112': 2.37452649881365, '4.122.55.111': 2.1210324004570342, '10.1.2.29': 2.0963101932115142, '10.1.4.42': 1.871431579860198, '10.1.4.46': 1.8537006820031514, '10.1.4.47': 1.8537006820031514, '10.1.4.43': 1.7139002092768365, '10.1.3.32': 1.6884684833213002, '10.1.3.33': 1.677860285774741, '9.66.11.14': 1.6384527379175453, '10.1.2.26': 1.5614858036097887, '10.1.2.28': 1.5614858036097887, '10.1.4.48': 1.5614858036097887, '10.1.4.49': 1.5614858036097887, '10.1.2.27': 1.5342251615770417, '10.1.2.22': 1.494420868877221, '9.66.11.13': 1.4185346976039055, '10.1.2.25': 1.4035009548422075, '10.1.4.45': 1.4035009548422075, '10.1.4.44': 1.4013363367699925, '10.1.3.34': 1.3511845824332904, '9.66.11.12': 1.2149787745319407, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.2': 0.0}
# Elbow's x:  1 , y:  3.8187487181851627 , value:  1.6604543756768502

# First IP:  4.122.55.3
# {'4.122.55.2': 5.484617437405683, '4.122.55.5': 5.035453118331749, '4.122.55.7': 4.884321720673894, '4.122.55.24': 4.86835769974308, '4.122.55.22': 4.864680370430526, '4.122.55.25': 4.864680370430526, '4.122.55.23': 4.513555491996767, '4.122.55.26': 4.513555491996767, '4.122.55.4': 3.88318113591417, '4.122.55.250': 3.596387521794313, '4.122.55.6': 3.4656633150594787, '10.1.2.29': 3.257242162419005, '4.122.55.115': 2.991234558095348, '4.122.55.21': 2.9554352880346837, '4.122.55.117': 2.6719951470342447, '10.1.2.26': 2.634412895500349, '10.1.2.28': 2.5978252899821714, '10.1.4.44': 2.562268305977484, '4.122.55.113': 2.5347824676654507, '4.122.55.112': 2.5074343100225596, '4.122.55.114': 2.4371602625077013, '9.66.11.13': 2.3740662658256424, '4.122.55.111': 2.2873296599401285, '10.1.2.25': 2.2690264807652962, '10.1.4.45': 2.1960387278372355, '9.66.11.12': 2.1785589040304956, '10.1.4.48': 2.094199551654944, '10.1.4.49': 2.094199551654944, '10.1.2.27': 2.066938909622197, '9.66.11.14': 2.0498843133284734, '10.1.3.34': 1.5631067273353256, '10.1.4.42': 1.491695684408378, '10.1.4.46': 1.3270890774020354, '10.1.4.47': 1.3270890774020354, '10.1.3.32': 1.3182408964973658, '10.1.3.33': 1.3182408964973658, '10.1.4.43': 1.3182408964973658, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.3': 0.0}
# Elbow's x:  30 , y:  1.5631067273353256 , value:  0.41536654306620013

# First IP:  4.122.55.4
# {'4.122.55.3': 3.8365119976633073, '4.122.55.2': 3.5497183835434507, '4.122.55.250': 3.5497183835434507, '4.122.55.5': 3.529093181443641, '4.122.55.7': 3.4754938696287545, '4.122.55.6': 3.4189941768086163, '4.122.55.22': 2.932861654815076, '4.122.55.24': 2.932861654815076, '4.122.55.25': 2.932861654815076, '4.122.55.21': 2.7987807966943943, '4.122.55.23': 2.781312267572672, '4.122.55.26': 2.781312267572672, '4.122.55.115': 2.6862476530371566, '4.122.55.117': 2.625326008783382, '4.122.55.113': 2.4881133294145883, '4.122.55.112': 2.216227633802597, '4.122.55.114': 2.166739483694365, '4.122.55.111': 2.0754075150380933, '10.1.2.29': 1.7369210828969452, '10.1.4.42': 1.491695684408378, '9.66.11.13': 1.4185346976039055, '10.1.2.27': 1.3740756947372454, '10.1.3.34': 1.3511845824332904, '10.1.4.44': 1.3444886601871682, '10.1.4.45': 1.3444886601871682, '9.66.11.14': 1.3228118689628199, '10.1.3.32': 1.3182408964973658, '10.1.3.33': 1.3182408964973658, '10.1.4.43': 1.3182408964973658, '10.1.2.25': 1.2433514880024112, '10.1.2.26': 1.2433514880024112, '10.1.2.28': 1.2433514880024112, '10.1.4.48': 1.2433514880024112, '10.1.4.49': 1.2433514880024112, '10.1.4.46': 1.2171037243126088, '10.1.4.47': 1.2171037243126088, '9.66.11.12': 1.2149787745319407, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.4': 0.0}
# Elbow's x:  6 , y:  2.932861654815076 , value:  0.4861325219935404

# First IP:  4.122.55.5
# {'4.122.55.3': 5.025467802322624, '4.122.55.6': 3.9920232208185094, '4.122.55.4': 3.5657770036853784, '4.122.55.2': 3.4556779990503537, '4.122.55.250': 3.4556779990503537, '4.122.55.7': 3.4242943859515322, '4.122.55.22': 3.3843453515799093, '4.122.55.24': 3.3843453515799093, '4.122.55.25': 3.3843453515799093, '4.122.55.23': 3.2327959643375053, '4.122.55.26': 3.2327959643375053, '4.122.55.21': 3.148327701646619, '4.122.55.111': 2.9355895767401483, '4.122.55.113': 2.815071373288026, '4.122.55.115': 2.8138945098680908, '4.122.55.117': 2.752972865614316, '4.122.55.114': 2.4271749464985763, '4.122.55.112': 2.4251774695965107, '10.1.2.29': 1.6428806984038484, '10.1.3.34': 1.5631067273353256, '9.66.11.13': 1.5266780397981674, '10.1.4.42': 1.491695684408378, '10.1.2.26': 1.4552736329044467, '10.1.2.28': 1.4552736329044467, '10.1.4.46': 1.4390037724338995, '10.1.4.47': 1.4390037724338995, '10.1.3.33': 1.4301555915292297, '10.1.4.43': 1.4301555915292297, '9.66.11.14': 1.4290258692146443, '10.1.4.44': 1.3444886601871682, '10.1.4.45': 1.3444886601871682, '9.66.11.12': 1.3311706780030206, '10.1.3.32': 1.3182408964973658, '10.1.2.25': 1.2433514880024112, '10.1.2.27': 1.2433514880024112, '10.1.4.48': 1.2433514880024112, '10.1.4.49': 1.2433514880024112, '10.1.2.22': 1.1254624962725082, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.5': 0.0}
# Elbow's x:  18 , y:  1.6428806984038484 , value:  0.7025228001241395

# First IP:  4.122.55.6
# {'4.122.55.5': 3.952520386719403, '4.122.55.2': 3.4161751649512473, '4.122.55.3': 3.4161751649512473, '4.122.55.4': 3.4161751649512473, '4.122.55.250': 3.4161751649512473, '4.122.55.7': 3.3104670203010365, '4.122.55.22': 2.910906672911879, '4.122.55.24': 2.910906672911879, '4.122.55.25': 2.910906672911879, '4.122.55.21': 2.7768258147911973, '4.122.55.23': 2.759357285669475, '4.122.55.26': 2.759357285669475, '4.122.55.115': 2.6642926711339596, '4.122.55.117': 2.6033710268801853, '4.122.55.111': 2.501653732171224, '4.122.55.113': 2.4661583475113913, '4.122.55.112': 2.3856746354974043, '4.122.55.114': 2.309131450586314, '10.1.2.29': 1.6033778643047418, '10.1.4.42': 1.491695684408378, '9.66.11.13': 1.4185346976039057, '10.1.3.34': 1.3511845824332904, '10.1.4.44': 1.3444886601871682, '10.1.4.45': 1.3444886601871682, '9.66.11.14': 1.3228118689628199, '10.1.3.32': 1.3182408964973658, '10.1.3.33': 1.3182408964973658, '10.1.4.43': 1.3182408964973658, '10.1.2.25': 1.2433514880024112, '10.1.2.26': 1.2433514880024112, '10.1.2.28': 1.2433514880024112, '10.1.2.27': 1.2433514880024112, '10.1.4.48': 1.2433514880024112, '10.1.4.49': 1.2433514880024112, '10.1.4.46': 1.2171037243126088, '10.1.4.47': 1.2171037243126088, '9.66.11.12': 1.2149787745319407, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.6': 0.0}
# Elbow's x:  18 , y:  1.6033778643047418 , value:  0.5940714063852082

# First IP:  4.122.55.7
# {'4.122.55.3': 4.849320342580145, '4.122.55.4': 3.4871616297858687, '4.122.55.5': 3.4242943859515322, '4.122.55.2': 3.3104670203010365, '4.122.55.6': 3.3104670203010365, '4.122.55.250': 3.3104670203010365, '4.122.55.24': 2.9608890325543635, '4.122.55.22': 2.7576362120504547, '4.122.55.25': 2.7576362120504547, '4.122.55.23': 2.6060868248080507, '4.122.55.26': 2.6060868248080507, '4.122.55.21': 2.4494304288169557, '4.122.55.115': 2.336897285159718, '4.122.55.114': 2.317250671586599, '4.122.55.117': 2.2759756409059433, '4.122.55.113': 2.1387629615371497, '4.122.55.111': 1.9653085104030685, '4.122.55.112': 1.9653085104030685, '10.1.2.29': 1.6717946447673488, '10.1.4.44': 1.5186135852999858, '10.1.4.42': 1.491695684408378, '10.1.2.25': 1.417476413115229, '10.1.2.26': 1.417476413115229, '10.1.2.28': 1.417476413115229, '10.1.3.34': 1.3511845824332904, '10.1.4.45': 1.3444886601871682, '10.1.3.32': 1.3182408964973658, '10.1.3.33': 1.3182408964973658, '10.1.4.43': 1.3182408964973658, '9.66.11.13': 1.3128265529536947, '10.1.2.27': 1.2433514880024112, '10.1.4.48': 1.2433514880024112, '10.1.4.49': 1.2433514880024112, '9.66.11.14': 1.2171037243126088, '10.1.4.46': 1.2171037243126088, '10.1.4.47': 1.2171037243126088, '9.66.11.12': 1.1092706298817299, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.7': 0.0}
# Elbow's x:  1 , y:  3.4871616297858687 , value:  1.2992914689599404

# First IP:  4.122.55.21
# {'4.122.55.22': 4.558293648646308, '4.122.55.24': 4.558293648646308, '4.122.55.25': 4.558293648646308, '4.122.55.23': 4.4067442614039045, '4.122.55.26': 4.4067442614039045, '4.122.55.2': 3.2641147935698958, '4.122.55.117': 3.129436818263307, '4.122.55.5': 3.050479923224865, '4.122.55.115': 3.0346345724631156, '4.122.55.3': 2.8476021936038043, '4.122.55.113': 2.8365002488405473, '4.122.55.4': 2.7376168405143777, '4.122.55.6': 2.71848087046855, '4.122.55.250': 2.6275178358793534, '4.122.55.111': 2.4711627714654156, '4.122.55.7': 2.376598712479825, '10.1.4.47': 2.297752671034806, '4.122.55.114': 2.2934391617962935, '10.1.4.46': 2.2929799735794765, '10.1.4.42': 2.2154912861738505, '4.122.55.112': 2.2005353450125766, '10.1.2.29': 2.1733271535840997, '9.66.11.13': 2.0673860305598715, '10.1.2.22': 2.027270730436084, '9.66.11.14': 1.9913606251358675, '10.1.4.43': 1.9820109763404081, '10.1.3.33': 1.9459710528383127, '9.66.11.12': 1.9187565607303823, '10.1.3.32': 1.8446645553530077, '10.1.3.34': 1.3821479772489864, '10.1.2.27': 1.239994836616564, '10.1.2.26': 1.2192559829711564, '10.1.2.28': 1.2192559829711564, '10.1.4.44': 1.2104078020664866, '10.1.4.45': 1.2104078020664866, '10.1.2.23': 1.1404688639724372, '10.1.2.24': 1.1404688639724372, '10.1.2.25': 1.1092706298817299, '10.1.4.48': 1.1092706298817299, '10.1.4.49': 1.1092706298817299, '4.122.55.21': 0.0}
# Elbow's x:  5 , y:  3.2641147935698958 , value:  1.00795149252742

# First IP:  4.122.55.22
# {'4.122.55.24': 6.947563438467948, '4.122.55.25': 6.947563438467948, '4.122.55.23': 6.796014051225544, '4.122.55.26': 6.796014051225544, '4.122.55.3': 4.759188396880689, '4.122.55.21': 4.560634769527351, '4.122.55.2': 3.718671088178997, '10.1.2.29': 3.4457642926643746, '4.122.55.5': 3.288838694039198, '4.122.55.117': 3.1317779391443494, '4.122.55.115': 3.0369756933441585, '10.1.4.47': 2.977352869651958, '4.122.55.4': 2.8740388195161017, '4.122.55.6': 2.8549028494702737, '4.122.55.113': 2.8388413697215897, '4.122.55.250': 2.763939814881077, '4.122.55.7': 2.6871456165943663, '9.66.11.13': 2.605831248840118, '4.122.55.111': 2.5754406841590667, '10.1.2.26': 2.5289209219505127, '10.1.2.28': 2.492333316432335, '10.1.4.44': 2.456776332427647, '4.122.55.114': 2.295780282677336, '10.1.4.46': 2.295321094460519, '9.66.11.14': 2.2843777036472734, '10.1.4.42': 2.217832407054893, '4.122.55.112': 2.2028764658936195, '10.1.4.43': 2.1730912630392054, '10.1.2.25': 2.1635345072154597, '9.66.11.12': 2.151709064126056, '10.1.3.33': 2.13705133953711, '10.1.4.45': 2.090546754287399, '10.1.2.22': 2.076746326684159, '10.1.3.32': 2.035744842051805, '10.1.4.48': 1.9887075781051076, '10.1.4.49': 1.9887075781051076, '10.1.2.27': 1.9614469360723605, '10.1.3.34': 1.809245913881074, '10.1.2.24': 1.3658227410786277, '10.1.2.23': 1.1899444602205118, '4.122.55.22': 0.0}
# Elbow's x:  4 , y:  4.759188396880689 , value:  1.8382720269915165

# First IP:  4.122.55.23
# {'4.122.55.22': 6.792108950835091, '4.122.55.24': 6.792108950835091, '4.122.55.25': 6.792108950835091, '4.122.55.26': 6.792108950835091, '4.122.55.21': 4.405180281894494, '4.122.55.3': 4.404158418056478, '4.122.55.2': 3.5632166005461405, '10.1.2.29': 3.441859192273922, '4.122.55.5': 3.1333842064063413, '4.122.55.117': 2.976323451511493, '10.1.4.47': 2.9734477692615053, '4.122.55.115': 2.8815212057113015, '4.122.55.4': 2.718584331883245, '4.122.55.6': 2.699448361837417, '4.122.55.113': 2.683386882088733, '4.122.55.250': 2.6084853272482205, '9.66.11.13': 2.6019261484496656, '4.122.55.7': 2.53169112896151, '10.1.2.26': 2.52501582156006, '10.1.2.28': 2.4884282160418825, '10.1.4.44': 2.4528712320371944, '4.122.55.111': 2.41998619652621, '10.1.4.46': 2.2914159940700665, '9.66.11.14': 2.280472603256821, '10.1.4.42': 2.21392730666444, '10.1.4.43': 2.169186162648753, '10.1.2.25': 2.1596294068250073, '9.66.11.12': 2.147803963735603, '4.122.55.114': 2.1403257950444794, '10.1.3.33': 2.1331462391466576, '10.1.4.45': 2.086641653896946, '10.1.2.22': 2.072841226293706, '4.122.55.112': 2.0474219782607626, '10.1.3.32': 2.0318397416613525, '10.1.4.48': 1.984802477714655, '10.1.4.49': 1.984802477714655, '10.1.2.27': 1.9575418356819079, '10.1.3.34': 1.8053408134906213, '10.1.2.24': 1.361917640688175, '10.1.2.23': 1.1860393598300591, '4.122.55.23': 0.0}
# Elbow's x:  4 , y:  4.405180281894494 , value:  2.3859068051025805

# First IP:  4.122.55.24
# {'4.122.55.22': 6.946707414401106, '4.122.55.25': 6.946707414401106, '4.122.55.23': 6.795158027158702, '4.122.55.26': 6.795158027158702, '4.122.55.3': 4.762009702126401, '4.122.55.21': 4.559778745460509, '4.122.55.2': 3.717815064112155, '10.1.2.29': 3.4449082685975325, '4.122.55.5': 3.2879826699723558, '4.122.55.117': 3.1309219150775074, '4.122.55.115': 3.0361196692773165, '10.1.4.47': 2.9764968455851157, '4.122.55.7': 2.8895424130314336, '4.122.55.4': 2.8731827954492597, '4.122.55.6': 2.8540468254034317, '4.122.55.113': 2.837985345654748, '4.122.55.250': 2.763083790814235, '9.66.11.13': 2.604975224773276, '4.122.55.111': 2.5745846600922246, '10.1.2.26': 2.5280648978836706, '10.1.2.28': 2.491477292365493, '10.1.4.44': 2.455920308360805, '4.122.55.114': 2.294924258610494, '10.1.4.46': 2.294465070393677, '9.66.11.14': 2.2835216795804314, '10.1.4.42': 2.216976382988051, '4.122.55.112': 2.2020204418267775, '10.1.4.43': 2.1722352389723634, '10.1.2.25': 2.1626784831486177, '9.66.11.12': 2.1508530400592134, '10.1.3.33': 2.136195315470268, '10.1.4.45': 2.089690730220557, '10.1.2.22': 2.0758903026173168, '10.1.3.32': 2.034888817984963, '10.1.4.48': 1.9878515540382655, '10.1.4.49': 1.9878515540382655, '10.1.2.27': 1.9605909120055185, '10.1.3.34': 1.8083898898142319, '10.1.2.24': 1.3649667170117856, '10.1.2.23': 1.1890884361536698, '4.122.55.24': 0.0}
# Elbow's x:  4 , y:  4.762009702126401 , value:  1.8309173683664088

# First IP:  4.122.55.25
# {'4.122.55.22': 6.948120348512237, '4.122.55.24': 6.948120348512237, '4.122.55.23': 6.796570961269833, '4.122.55.26': 6.796570961269833, '4.122.55.3': 4.759745306924978, '4.122.55.21': 4.56119167957164, '4.122.55.2': 3.719227998223286, '10.1.2.29': 3.4463212027086634, '4.122.55.5': 3.2893956040834866, '4.122.55.117': 3.1323348491886382, '4.122.55.115': 3.0375326033884473, '10.1.4.47': 2.9779097796962466, '4.122.55.4': 2.8745957295603906, '4.122.55.6': 2.8554597595145625, '4.122.55.113': 2.839398279765879, '4.122.55.250': 2.764496724925366, '4.122.55.7': 2.687702526638655, '9.66.11.13': 2.606388158884407, '4.122.55.111': 2.5759975942033555, '10.1.2.26': 2.5294778319948015, '10.1.2.28': 2.4928902264766237, '10.1.4.44': 2.457333242471936, '4.122.55.114': 2.2963371927216247, '10.1.4.46': 2.2958780045048077, '9.66.11.14': 2.2849346136915623, '10.1.4.42': 2.2183893170991817, '4.122.55.112': 2.2034333759379083, '10.1.4.43': 2.1736481730834942, '10.1.2.25': 2.1640914172597485, '9.66.11.12': 2.1522659741703443, '10.1.3.33': 2.137608249581399, '10.1.4.45': 2.091103664331688, '10.1.2.22': 2.0773032367284476, '10.1.3.32': 2.0363017520960938, '10.1.4.48': 1.9892644881493964, '10.1.4.49': 1.9892644881493964, '10.1.2.27': 1.9620038461166494, '10.1.3.34': 1.8098028239253627, '10.1.2.24': 1.3663796511229165, '10.1.2.23': 1.1905013702648006, '4.122.55.25': 0.0}
# Elbow's x:  4 , y:  4.759745306924978 , value:  1.8382720269915147

# First IP:  4.122.55.26
# {'4.122.55.22': 6.792744475352517, '4.122.55.23': 6.792744475352517, '4.122.55.24': 6.792744475352517, '4.122.55.25': 6.792744475352517, '4.122.55.21': 4.405815806411921, '4.122.55.3': 4.404793942573904, '4.122.55.2': 3.5638521250635664, '10.1.2.29': 3.442494716791348, '4.122.55.5': 3.134019730923767, '4.122.55.117': 2.976958976028919, '10.1.4.47': 2.974083293778931, '4.122.55.115': 2.882156730228728, '4.122.55.4': 2.719219856400671, '4.122.55.6': 2.7000838863548435, '4.122.55.113': 2.6840224066061595, '4.122.55.250': 2.609120851765647, '9.66.11.13': 2.6025616729670915, '4.122.55.7': 2.532326653478936, '10.1.2.26': 2.525651346077486, '10.1.2.28': 2.4890637405593083, '10.1.4.44': 2.4535067565546207, '4.122.55.111': 2.4206217210436365, '10.1.4.46': 2.2920515185874923, '9.66.11.14': 2.281108127774247, '10.1.4.42': 2.2145628311818664, '10.1.4.43': 2.169821687166179, '10.1.2.25': 2.160264931342433, '9.66.11.12': 2.148439488253029, '4.122.55.114': 2.1409613195619057, '10.1.3.33': 2.1337817636640835, '10.1.4.45': 2.0872771784143724, '10.1.2.22': 2.0734767508111323, '4.122.55.112': 2.048057502778189, '10.1.3.32': 2.0324752661787784, '10.1.4.48': 1.985438002232081, '10.1.4.49': 1.985438002232081, '10.1.2.27': 1.958177360199334, '10.1.3.34': 1.8059763380080474, '10.1.2.24': 1.362553165205601, '10.1.2.23': 1.1866748843474852, '4.122.55.26': 0.0}
# Elbow's x:  4 , y:  4.405815806411921 , value:  2.3859068051025787

# First IP:  4.122.55.250
# {'4.122.55.2': 3.547240399739303, '4.122.55.3': 3.547240399739303, '4.122.55.4': 3.547240399739303, '4.122.55.5': 3.4165161930044685, '4.122.55.6': 3.4165161930044685, '4.122.55.7': 3.2963212763397745, '4.122.55.22': 2.8202846663759034, '4.122.55.24': 2.8202846663759034, '4.122.55.25': 2.8202846663759034, '4.122.55.117': 2.7181918395329685, '4.122.55.21': 2.686203808255222, '4.122.55.23': 2.6687352791334997, '4.122.55.26': 2.6687352791334997, '4.122.55.115': 2.5736706645979845, '4.122.55.113': 2.375536340975416, '4.122.55.114': 2.309131450586314, '4.122.55.112': 2.216227633802597, '4.122.55.111': 1.9653085104030685, '10.1.2.29': 1.7344430990927975, '9.66.11.14': 1.5282546881515784, '10.1.4.42': 1.491695684408378, '9.66.11.12': 1.4204215937206994, '9.66.11.13': 1.4185346976039057, '10.1.2.27': 1.3740756947372454, '10.1.3.34': 1.3511845824332904, '10.1.4.44': 1.3444886601871682, '10.1.4.45': 1.3444886601871682, '10.1.3.32': 1.3182408964973658, '10.1.3.33': 1.3182408964973658, '10.1.4.43': 1.3182408964973658, '10.1.2.25': 1.2433514880024112, '10.1.2.26': 1.2433514880024112, '10.1.2.28': 1.2433514880024112, '10.1.4.48': 1.2433514880024112, '10.1.4.49': 1.2433514880024112, '10.1.4.46': 1.2171037243126088, '10.1.4.47': 1.2171037243126088, '10.1.2.22': 1.013547801240644, '10.1.2.23': 1.013547801240644, '10.1.2.24': 1.013547801240644, '4.122.55.250': 0.0}
# Elbow's x:  6 , y:  2.8202846663759034 , value:  0.4760366099638711

# Louvain method - ina metoda by mozno dala lepsie vysledky
# CALL gds.louvain.stream({ nodeProjection: 'IP_ADDRESS', relationshipProjection: 'DEPENDENCY'})
# YIELD nodeId, communityId, intermediateCommunityIds RETURN gds.util.asNode(nodeId).address AS address,
# communityId, intermediateCommunityIds ORDER BY address ASC
# CLUSTERS with IDs:
# 450 - 10.1.1.14
# 38 - 10.1.2.22, 10.1.2.23, 10.1.2.24, 10.1.3.32, 10.1.3.33, 10.1.3.34, 10.1.4.42, 10.1.4.43, 10.1.4.46,
#      10.1.4.47, 4.122.55.22, 4.122.55.23, 4.122.55.25, 4.122.55.26, 9.66.11.12, 9.66.11.13, 9.66.11.14
# 41 - 10.1.2.25, 10.1.2.26, 10.1.2.27, 10.1.2.28, 10.1.2.29, 10.1.4.44, 10.1.4.45, 10.1.4.48, 10.1.4.49
# 134 - 4.122.55.1
# 37 - 4.122.55.111, 4.122.55.112, 4.122.55.113, 4.122.55.114, 4.122.55.115, 4.122.55.117, 4.122.55.2, 4.122.55.21,
#      4.122.55.24, 4.122.55.250, 4.122.55.3, 4.122.55.4, 4.122.55.5, 4.122.55.6, 4.122.55.7
# 252 - 4.122.55.214
# 302 - 4.122.55.221
# 301 - 4.122.55.229
# 151 - 4.122.55.254
# 201 - 4.122.55.255
# 202 - 4.122.55.31
# 149 - 4.122.55.34
# 138 - 4.122.55.35
# 176 - 4.122.55.36

# Label Propagation method
# CALL gds.labelPropagation.stream({ nodeProjection: 'IP_ADDRESS', relationshipProjection: 'DEPENDENCY'})
# YIELD nodeId, communityId AS Community RETURN gds.util.asNode(nodeId).address AS address, Community ORDER BY
# address DESC
# CLUSTERS with IDs:
# 454 - 10.1.1.14
# 27 - 10.1.2.22, 10.1.2.23, 10.1.2.24, 10.1.3.32, 10.1.3.33, 10.1.4.42, 10.1.4.43, 10.1.4.46,
#      10.1.4.47, 9.66.11.14
# 35 - 10.1.2.25, 10.1.2.26, 10.1.2.27, 10.1.2.28, 10.1.2.29, 10.1.4.44, 10.1.4.45, 10.1.4.48,
#      10.1.4.49,
# 18 - 10.1.3.34, 4.122.55.111, 4.122.55.112, 4.122.55.113, 4.122.55.114, 4.122.55.115,
#      4.122.55.117, 4.122.55.2, 4.122.55.21, 4.122.55.22, 4.122.55.23, 4.122.55.24,
#      4.122.55.25, 4.122.55.250, 4.122.55.26, 4.122.55.3, 4.122.55.4, 4.122.55.5,
#      4.122.55.6, 4.122.55.7, 9.66.11.12, 9.66.11.13
# 134 - 4.122.55.1
# 256 - 4.122.55.214
# 306 - 4.122.55.221
# 305 - 4.122.55.229
# 151 - 4.122.55.254
# 205 - 4.122.55.255
# 206 - 4.122.55.31
# 149 - 4.122.55.34
# 138 - 4.122.55.35
# 180 - 4.122.55.36

# Weakly connected component
# CALL gds.wcc.stream({ nodeProjection: 'IP_ADDRESS', relationshipProjection: 'DEPENDENCY'})
# YIELD nodeId, componentId RETURN gds.util.asNode(nodeId).address AS address, componentId ORDER BY address ASC
# vsetky podstatne komponenty tvoria jednu weakly connected components

# Modularity optimization - pretecie halda

# Strongly connected components
# CALL gds.alpha.scc.stream({ nodeProjection: 'IP_ADDRESS', relationshipProjection: 'DEPENDENCY'})
# YIELD nodeId, componentId RETURN gds.util.asNode(nodeId).address AS address, componentId ORDER BY address ASC
# 450 - 10.1.1.14,
# 45 - 10.1.2.22, 10.1.3.32, 10.1.3.33, 10.1.4.42, 10.1.4.43, 10.1.4.46, 10.1.4.47,
#      9.66.11.14
# 164 - 10.1.2.23, 10.1.2.24
# 0 - 10.1.2.25, 10.1.2.26, 10.1.2.27, 10.1.2.28, 10.1.2.29, 10.1.3.34, 10.1.4.44,
#     10.1.4.45, 10.1.4.48, 10.1.4.49, 4.122.55.111, 4.122.55.112, 4.122.55.113,
#     4.122.55.114, 4.122.55.115, 4.122.55.117, 4.122.55.2, 4.122.55.21, 4.122.55.22,
#     4.122.55.24, 4.122.55.25, 4.122.55.250, 4.122.55.3, 4.122.55.4, 4.122.55.5,
#     4.122.55.6, 4.122.55.7, 9.66.11.12, 9.66.11.13
# 134 - 4.122.55.1
# 252 - 4.122.55.214
# 302 - 4.122.55.221
# 301 - 4.122.55.229
# 96 - 4.122.55.23
# 151 - 4.122.55.254
# 201 - 4.122.55.255
# 19 - 4.122.55.26
# 202 - 4.122.55.31
# 149 - 4.122.55.34
# 138 - 4.122.55.35
# 176 - 4.122.55.36

# Triangle counting - vypisuje iba trojuholniky

# ==============================================
# Vyhodnotenie nad reálnymi dátami z MU
# Extrémne všetkých prevyšuje time server (MU),
# potom nasleduje nejaký jihomoravský kraj, nejaký školský server pre nejakú strednú školu (oba mimo MU)
# potom z MU ide FTP server, kt. je vraj jeden z najvyťaženejších v rámci CESNETu, name server, mail server,
# ARES server pre fakultu informatiky - router, firewall, DNS, DHCP,
# eduroam server

# 147.251.48.140 123 - časový server podľa protokolu

# CALL gds.pageRank.stream({nodeQuery: 'MATCH (n) RETURN id(n) AS id', relationshipQuery: 'MATCH
# (ip1:IP_ADDRESS)-[r:COMMUNICATES_WITH]->(ip2:IP_ADDRESS) WHERE NOT ip1.address STARTS WITH "147.251."
# AND ip2.address STARTS WITH "147.251." RETURN DISTINCT id(ip1) AS source, id(ip2) AS target'})
# YIELD nodeId, score RETURN gds.util.asNode(nodeId).address AS address, score ORDER BY score DESC, address ASC
# dával dobré výsledky


# TODO link prediction - na zaklade dat z predchadzajuceho casoveho okna urcit, kde by mohla byt hrana dependency
#  do buducna, pricom moze byt aj medzi takymi dvoma vrcholmi, kde je v aktualnom casovom okne communication
#  dalsia vec - budeme mat v databazi velke mnozstvo hran roznych typov, kde typ bude podla cisla protokolu
#  my predpovedame pre dany typ hrany, ze nejake zariadenie by mohlo vyzadovat takuto komunikaciu, napr. NTP, DNS
#  a zmeriame precision a accuracy podla toho, kolko zariadeni bude v ramci navrhnutych zariadeni spravnych a kolko
#  spravnych ostane vonku. Podla toho mozeme urcit, ci sa da brat este viac dependencies zo zoznamu alebo nie.
#  Elbow rule dava prilis male thresholdy, bude potreba lepsie pravidlo.

# https://apps.dtic.mil/sti/pdfs/ADA550373.pdf Determining Asset Criticality for Cyber Defense
# PageRank sa vraj nedá použiť, lebo nie všetky závislosti majú rovnakú silu a vlastnosti, ale keď použijeme
# PageRank a link prediction na komunikáciu vždy na tom istom porte, tak by to mohlo dávať väčší zmysel.

# Určovanie kritických zariadení by potom fungovalo tak, že dostaneme na vstupe:
# protokol a PageRank
# device a k nemu nejaké závislosti na dôležitých portoch

# PageRank aplikovaný na jednotlivé dst porty
# 443 - vychadza IS server
# 53 - DNS servery,
# 80 - fakultny multifunkcny server
# 123 - pyrrha NTP server
