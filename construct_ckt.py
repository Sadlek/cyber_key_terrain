# Algoritmus
# 1. vezmi IP adresy, kt. boli oznacene ako dolezite
# 2. zisti ich IP adresy
# 3. pozri logy
import json
from pprint import pprint
from neo4j import GraphDatabase, basic_auth
from pprint import pprint


BOLT = 'bolt://localhost:7687'
DRIVER = GraphDatabase.driver(BOLT, auth=basic_auth("neo4j", "ne04jcrus03"), encrypted=False)


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


def measure_link_prediction(list_of_ips):
    function_result = []
    for first_ip in list_of_ips:
        for second_ip in list_of_ips:
            if first_ip == second_ip:
                continue

            # Adamic-Adar
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
                # score = result.data()[0]['score']
                # if score != 0:
                lp_metrics = result.data()[0]
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
# 3.) Podla link prediction sa predpovie, ake zavislosti sa v budcnosti vytvoria - tie su neorientovane,
# pokial node zvykne odpovedat na prichadzajuce spojenia alebo vysielat spojenia, tak dame smer, inak nechame
# neorientovanu hranu

def compute_ckt():
    page_rank_result = []
    with (DRIVER.session()) as session:
        page_rank = session.run("CALL gds.pageRank.stream( "
                             "{ "
                             "nodeProjection: 'IP_ADDRESS', "
                             "relationshipProjection: 'COMMUNICATES_WITH' "
                             "} "
                             ") "
                             "YIELD nodeId, score "
                             "RETURN gds.util.asNode(nodeId).address AS address, score "
                             "ORDER BY score DESC, address ASC")
        page_rank_result = page_rank.data()
        pprint(page_rank_result)

    ckt = {}
    for list_item in page_rank_result:
        # list_item['address']
        if list_item['score'] >= 4:
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
            if prevailing_outcoming_connections(first_ip, second_ip) and list_item['score_aa'] >= 0.5:
                ckt[second_ip] = list_item['score_aa']
    print(ckt)

    for list_item in measure_link_prediction(flow_ips):
        first_ip = list_item['first']
        second_ip = list_item['second']
        if first_ip in ckt:
            if prevailing_outcoming_connections(first_ip, second_ip) and list_item['score_aa'] >= 0.5:
                ckt[second_ip] = list_item['score_aa']
    print(ckt)


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

# MATCH (ip1:IP_ADDRESS)-[r:COMMUNICATES_WITH]->(ip2:IP_ADDRESS) WHERE r.end <= 1553008187739  AND r.start >= 1552994894805 AND ip1.address STARTS WITH '10.' OR ip1.address STARTS WITH '4.122.' OR ip1.address STARTS WITH '9.66.' RETURN DISTINCT ip1.address, ip2.address

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