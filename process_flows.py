import json
import csv
from construct_ckt import create_connections_in_database


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


def create_flows_from_csv(start_line, input_file='data/flows-202203011000.csv'):
    # Date first seen, Date last seen, Protocol, Src IP Address, Src Port, Dst IP Address, Dst Port, TCP Flags, Packets, Bytes
    counter = 0
    with open(input_file, newline='') as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        for row in csv_reader:
            counter += 1
            print(counter)
            if counter > start_line:
                create_connections_in_database(row[3], row[5], row[0], row[1])
