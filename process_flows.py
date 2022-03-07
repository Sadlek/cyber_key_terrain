import json
import csv
from construct_ckt import create_connections_in_database
from neo4j import GraphDatabase, basic_auth


BOLT = 'bolt://localhost:7687'
DRIVER = GraphDatabase.driver(BOLT, auth=basic_auth("neo4j", "ne04jcrus03"), encrypted=False)
# DRIVER = GraphDatabase.driver(BOLT, auth=basic_auth("neo4j", "Neo4jPas"), encrypted=False)


# TODO
# "10.7.101.12" == "9.66.11.12"
def filter_ip(ip_address):
    output_lines = []
    with open(f'data_{ip_address}.json', 'w') as output_file:
        with open('data/data.json', 'r') as jsonfile:
            for line in jsonfile:
                data = json.loads(line)
                if data["destinationIPv4Address"] == ip_address or data["sourceIPv4Address"] == ip_address:
                    output_lines.append(data)
        json.dump(output_lines, fp=output_file)


def create_connection_with_all_params(start, end, proto, src_ip, src_port, dst_ip, dst_port, tcp_flags, packets, bytes):
    # Date first seen, Date last seen, Protocol, Src IP Address, Src Port, Dst IP Address, Dst Port, TCP Flags, Packets, Bytes
    with(DRIVER.session()) as session:
        session.run(
            "MERGE (a:IP_ADDRESS {address: $first_ip}) "
            "MERGE (b:IP_ADDRESS {address: $second_ip}) "
            "CREATE (a)-[:COMMUNICATES_WITH {start: $start, end: $end, proto: $proto, src_port: $src_port, dst_port: $dst_port, tcp_flags: $tcp_flags, packets: $packets, bytes: $bytes}]->(b)",
            **{'first_ip': src_ip, 'second_ip': dst_ip, 'start': start, 'end': end, 'proto': proto,
               'src_port': src_port, 'dst_port': dst_port, 'tcp_flags': tcp_flags, 'packets': packets, 'bytes': bytes})
    print("created")


def create_flows_from_csv(start_line, input_file='data/flows-202203011000.csv'):
    # Date first seen, Date last seen, Protocol, Src IP Address, Src Port, Dst IP Address, Dst Port, TCP Flags, Packets, Bytes
    counter = 0
    with open(input_file, newline='') as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        for row in csv_reader:
            counter += 1
            print(counter)
            if counter > start_line:
                # create_connections_in_database(row[3], row[5], row[0], row[1])
                create_connection_with_all_params(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7],
                                                  row[8], row[9])


def analyze_flows(input_file='data/flows-202203011000.csv'):
    other = 0
    source_mu_target_mu = 0
    source_mu_target_other = 0
    source_other_target_mu = 0
    source_other_target_other = 0
    counter = 0
    with open(input_file, newline='') as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        for row in csv_reader:
            counter += 1
            if counter % 1000 == 0:
                print(counter)
            if row[3].startswith('147.251.') or row[3].startswith('2001:718:80'):
                if row[5].startswith('147.251.') or row[5].startswith('2001:718:80'):
                    source_mu_target_mu += 1
                else:
                    source_mu_target_other += 1
            else:
                if row[5].startswith('147.251.') or row[5].startswith('2001:718:80'):
                    source_other_target_mu += 1
                else:
                    source_other_target_other += 1
                    if not row[3].startswith('195.113.') and not row[5].startswith('195.113.') and \
                            not row[3].startswith('195.178.') and not row[5].startswith('195.178.') and \
                            not row[3].startswith('78.128.') and not row[5].startswith('78.128.') and \
                            not row[3].startswith('10.') and not row[5].startswith('10.') and \
                            not row[3].startswith('192.168.') and not row[5].startswith('192.168.') and \
                            not row[3].startswith('172.') and not row[5].startswith('172.'):
                        print(row[3], row[5])
                        other += 1
    print(source_mu_target_mu)
    print(source_mu_target_other)
    print(source_other_target_mu)
    print(source_other_target_other)
    print(other)
