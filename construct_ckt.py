# Algoritmus
# 1. vezmi IP adresy, kt. boli oznacene ako dolezite
# 2. zisti ich IP adresy
# 3. pozri logy
import json
from pprint import pprint
from neo4j import GraphDatabase, basic_auth


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
    counter = 0
    with open(ip_flow_filename, 'r') as jsonfile:
        for line in jsonfile.readlines():
            data = json.loads(line)
            counter += 1
            # if data["biFlowStartMilliseconds"] >= start_timestamp and data["biFlowEndMilliseconds"] < end_timestamp:
            #     counter += 1
                # create_connections_in_database(data["sourceIPv4Address"], data["destinationIPv4Address"],
                #                                data["biFlowStartMilliseconds"],
                #                                data["biFlowEndMilliseconds"])
    return counter


def create_connections_in_database(src_ip, dst_ip, start, end):
    with(DRIVER.session()) as session:
        session.run(
            "MERGE (a:IP_ADDRESS {address: $first_ip}) "
            "MERGE (b:IP_ADDRESS {address: $second_ip}) "
            "CREATE (a)-[:COMMUNICATES_WITH {start: $start, end: $end}]->(b)",
            **{'first_ip': src_ip, 'second_ip': dst_ip, 'start': start, 'end': end})
    print("created")
