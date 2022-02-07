from pprint import pprint
import json


def filter_device(device_name):
    with open('data_modified.json', 'r') as jsonfile:
        with open(f'data_{device_name}.json', 'w') as output_file:
            for line in jsonfile.readlines():
                data = json.loads(line)
                if data['hostname'] == device_name:
                    json.dump(data, fp=output_file)
                    output_file.write("/n")


def filter_syslog_events(list_of_ip_addresses, input_file='data/data_syslog.json'):
    output_lines = []
    with open(f'data_filtered/data_syslog_filtered.json', 'w') as output_file:
        with open(input_file, 'r') as jsonfile:
            for line in jsonfile.readlines():
                data = json.loads(line)
                if data["fromhost_ip"] in list_of_ip_addresses:
                    output_lines.append(data)
        json.dump(output_lines, fp=output_file)


def filter_winlog_events(list_of_ip_addresses, input_file='data/data_winlog.json'):
    output_lines = []
    with open(f'data_filtered/data_winlog_filtered.json', 'w') as output_file:
        with open(input_file, 'r') as jsonfile:
            for line in jsonfile.readlines():
                data = json.loads(line)
                if data["host_ip"] in list_of_ip_addresses:
                    output_file.write(line)
                    # output_lines.append(data)
        # json.dump(output_lines, fp=output_file)


def filter_ip_flows(list_of_ip_addresses, input_file='data/data_ipflow.json'):
    output_lines = []
    with open(f'data_filtered/data_ipflow_filtered.json', 'w') as output_file:
        with open(input_file, 'r') as jsonfile:
            for line in jsonfile.readlines():
                data = json.loads(line)
                if data["destinationIPv4Address"] in list_of_ip_addresses or \
                        data["sourceIPv4Address"] in list_of_ip_addresses:
                    # output_lines.append(data)
                    output_file.write(line)
        # json.dump(output_lines, fp=output_file)


def filter_ip(ip_address):
    output_lines = []
    with open(f'data_{ip_address}.json', 'w') as output_file:
        with open('data/data.json', 'r') as jsonfile:
            for line in jsonfile.readlines():
                data = json.loads(line)
                if data["destinationIPv4Address"] == ip_address or data["sourceIPv4Address"] == ip_address:
                    # output_lines.append(data)
                    output_file.write(line)
        # json.dump(output_lines, fp=output_file)


# syslog - "10.7.101.12"
# IP flow - "9.66.11.12"
def compare_syslog_and_ip_flow(syslog_ip_address, flow_ip_address):
    pass


def get_dst_ips_that_communicated(src_ip_address, filename='data_9.66.11.12_ipflow.json'):
    dst_ips = set()
    with open(filename, 'r') as jsonfile:
        data = json.load(jsonfile)
        for item in data:
            if item["sourceIPv4Address"] == src_ip_address:
                dst_ips.add(item["destinationIPv4Address"])
    pprint(dst_ips)


def get_src_ips_that_communicated(dst_ip_address, filename='data_9.66.11.12_ipflow.json'):
    src_ips = set()
    with open(filename, 'r') as jsonfile:
        data = json.load(jsonfile)
        for item in data:
            if item["destinationIPv4Address"] == dst_ip_address:
                src_ips.add(item["sourceIPv4Address"])
    pprint(src_ips)


def get_syslog_program_names(fromhost_ip, filename='data_10.7.101.12_syslog.json'):
    program_names = set()
    app_names = set()
    with open(filename, 'r') as jsonfile:
        data = json.load(jsonfile)
        for item in data:
            if item["fromhost_ip"] == fromhost_ip:
                program_names.add(item["programname"])
                app_names.add(item["app_name"])
    pprint(program_names)
    pprint(app_names)


def get_logs(fromhost_ip, program_name, filename='data_10.7.101.12_syslog.json'):
    with open(filename, 'r') as jsonfile:
        data = json.load(jsonfile)
        for item in data:
            if item["fromhost_ip"] == fromhost_ip and item["programname"] == program_name:
                print(item["message"])


def get_log_messages(flow_filename='data_4.122.55.3_ipflow.json', syslog_filename='data_10.7.100.3_syslog.json'):
    # list_of_timestamps = []
    with open(flow_filename, 'r') as jsonfile:
        with open(syslog_filename, 'r') as syslog_file:
            flow_data = json.load(jsonfile)
            syslog_data = json.load(syslog_file)
            for flow_item in flow_data:
                if flow_item["sourceIPv4Address"] == "9.66.11.12" or \
                        flow_item["destinationIPv4Address"] == "9.66.11.12":
                    flow_start = flow_item["biFlowStartMilliseconds"]
                    flow_end = flow_item["biFlowEndMilliseconds"]
                    for syslog_entry in syslog_data:
                        timestamp = syslog_entry["timestamp"]
                        if flow_start <= timestamp <= flow_end:
                            message = syslog_entry["message"]
                            print(message)
    # pprint(list_of_timestamps)


def get_log_messages_extended(first_ip_flow, second_ip_flow, first_ip_logs, second_ip_logs,
                              flow_filename='data/data_ipflow.json', syslog_filename='data/data_syslog.json'):
    # TODO tata procedura sposobuje zamrznutie celeho Ubuntu, kvoli vytazeniu pamate, a vyzaduje restart celeho PC
    flow_data = []
    # syslog_data = []
    # with open(flow_filename, 'r') as flow_file:
    #     with open(syslog_filename, 'r') as syslog_file:
    #         for flow_line in flow_file.readlines():
    #             flow_data.append(json.loads(flow_line))
    #             for syslog_line in syslog_file.readlines():
    #                 syslog_data.append(json.loads(syslog_line))
    #
    # for flow_data_item in flow_data:
    #     for syslog_data_item in syslog_data:
    #         print("inside")
    #         if flow_data_item["sourceIPv4Address"] == first_ip_flow and flow_data_item["destinationIPv4Address"] == second_ip_flow or \
    #                 flow_data_item["sourceIPv4Address"] == second_ip_flow and flow_data_item["destinationIPv4Address"] == first_ip_flow:
    #             flow_start = flow_data_item["biFlowStartMilliseconds"]
    #             flow_end = flow_data_item["biFlowEndMilliseconds"]
    #             if syslog_data_item["fromhost_ip"] == first_ip_logs or syslog_data_item["fromhost_ip"] == second_ip_logs:
    #                 timestamp = syslog_data_item["timestamp"]
    #                 if flow_start <= timestamp <= flow_end:
    #                     message = syslog_data_item["message"]
    #                     print(message)


# TODO vyriešiť časové známky spolu s logmi
# "biFlowEndMilliseconds": 1552989621,213, "biFlowStartMilliseconds": 1552989621205
# "flowEndMilliseconds": 1552989621,205, "flowEndMilliseconds_Rev": 1552989621,213,
# "flowStartMilliseconds": 1552989621,205, "flowStartMilliseconds_Rev": 1552989621,213
# "timestamp": 1552989621,213


ip_flow = \
    {"applicationId": "50331701", "applicationName": "DNS_TCP", "bgpDestinationAsNumber": 3356, "bgpSourceAsNumber": 0,
        "biFlowEndMilliseconds": 1552989621213, "biFlowStartMilliseconds": 1552989621205, "destinationIPv4Address":
        "4.122.55.3", "destinationTransportPort": 53, "exercise_dst_ipv4_segment": "global",
        "extendedFlow": {"dns": "{\"questionCount\":1,\"crrType\":1,\"crrTtl\":600,\"qtype\":1,\"flagsCodesResponse\":"
                                "34176, \"flagsCodesRequest\":256,\"addtrecCountResponse\":1,\"crrRdata\":"
                                "\"0x047a3702\",\"addtrecCountRequest\":0, \"authrecCountRequest\":0,\"crrClass\":1,"
                                "\"crrName\":\"0x676f76636572742e6578\",\"answrecCountRequest\":0, \"qname\":"
                                "\"0x676f76636572742e6578\",\"crrRdataLen\":4,\"authrecCountResponse\":1,"
                                "\"answrecCountResponse\":1, \"id\":35621,\"qclass\":1}"},
        "flowEndMilliseconds": 1552989621205, "flowEndMilliseconds_Rev": 1552989621213,
        "flowStartMilliseconds": 1552989621205, "flowStartMilliseconds_Rev": 1552989621213, "ingressInterface": 0,
        "ipClassOfService": 0, "ipVersion": 4, "mplsLabelStackSection2_Rev": "0x000000", "mplsLabelStackSection3_Rev":
        "0x000000", "mplsLabelStackSection4_Rev": "0x000000", "mplsTopLabelStackSection_Rev": "0x000000",
        "octetDeltaCount": 56, "octetDeltaCount_Rev": 105, "packetDeltaCount": 1, "packetDeltaCount_Rev": 1,
        "protocolIdentifier": 17, "samplingAlgorithm": 0, "samplingInterval": 0, "sourceIPv4Address": "9.66.11.12",
        "sourceTransportPort": 39914, "timestamp": 1552989621213}


syslog_item = \
    {"app_name": "systemd", "exercise_segment": "blue-team-1", "facility": 3, "fromhost_ip": "10.7.101.12",
     "hostname": "mail", "message": " Created slice User Slice of root.", "programname": "systemd", "severity": 6,
     "timegenerated": "2019-03-19T11:00:12.298523+01:00", "timereported": "2019-03-19T10:01:01+01:00",
     "timestamp": 1552989612298}


# mail server - 9.66.11.12, 10.7.101.12
# global-dns  - 4.122.55.3, 10.7.100.3

# 9.66.11.12. as src IP communicated with
# {'172.16.1.1',
#  '212.5.11.84',
#  '27.3.0.196',
#  '4.122.55.221',
#  '4.122.55.3',
#  '4.122.55.5',
#  '77.51.161.30',
#  '8.8.8.8'}

# 9.66.11.12 as dst IP communicated with
# {'172.16.1.1',
#  '27.3.0.196',
#  '4.122.55.1',
#  '4.122.55.111',
#  '4.122.55.221',
#  '4.122.55.229',
#  '4.122.55.3',
#  '4.122.55.5',
#  '77.51.161.30',
#  '8.8.8.8'}

# 4.122.55.3 as src IP communicated with
# {'9.66.11.12'}

# 4.122.55.3 as dst IP communicated with
# {'9.66.11.12'}

# TODO
# 1.) zobrat IP adresy pre jednu sestinu - pre jeden modry tim a vyfiltrovat IP toky
# 2.) plus k tomu zobrat globalnu cast siete a MGMT
# pozor, komunikacia medzi zariadeniami v ramci jedneho tymu - neunikatne adresy
flow_ips = ['9.66.11.12', '9.66.11.13', '9.66.11.14', '10.1.2.22', '10.1.2.23', '10.1.2.24', '10.1.2.25', '10.1.2.26',
            '10.1.2.28', '10.1.2.27', '10.1.2.29', '10.1.3.32', '10.1.3.33', '10.1.3.34', '10.1.4.46', '10.1.4.47',
            '10.1.4.48', '10.1.4.49', '10.1.4.42', '10.1.4.43', '10.1.4.44', '10.1.4.45', '4.122.55.111',
            '4.122.55.112', '4.122.55.113', '4.122.55.114', '4.122.55.115', '4.122.55.116', '4.122.55.117',
            '4.122.55.2', '4.122.55.3', '4.122.55.4', '4.122.55.5', '4.122.55.6', '4.122.55.7', '4.122.55.21',
            '4.122.55.22', '4.122.55.23', '4.122.55.24', '4.122.55.25', '4.122.55.26', '4.122.55.250']
syslog_ips = ['10.7.101.12', '10.7.101.13', '10.7.101.25', '10.7.101.26', '10.7.101.28', '10.7.101.27', '10.7.101.29',
              '10.7.101.34', '10.7.101.48', '10.7.101.49', '10.7.101.44', '10.7.101.45', '10.7.100.111', '10.7.100.112',
              '10.7.100.113', '10.7.100.114', '10.7.100.115', '10.7.100.116', '10.7.100.2', '10.7.100.3', '10.7.100.4',
              '10.7.100.5', '10.7.100.6', '10.7.100.7', '10.7.100.21', '10.7.100.22', '10.7.100.23', '10.7.100.24',
              '10.7.100.25', '10.7.100.26']
winlog_ips = ['10.7.101.14', '10.7.101.22', '10.7.101.23', '10.7.101.24', '10.7.101.32', '10.7.101.33', '10.7.101.46',
              '10.7.101.47', '10.7.101.42', '10.7.101.43', '10.7.100.117', '10.7.100.250']

# BLUE TEAM 1 ======================
# Zoznam IP adries pre Blue Team 1
# mail.firechmel.ex
# 9.66.11.12
# 10.7.101.12

# dns.firechmel.ex
# 9.66.11.13
# 10.7.101.13

# www.firechmel.ex
# 9.66.11.14
# 10.7.101.14

# dc
# 10.1.2.22
# 10.7.101.22

# files
# 10.1.2.23
# 10.7.101.23

# backup
# 10.1.2.24
# 10.7.101.24

# menu
# 10.1.2.25
# 10.7.101.25

# db.chmel.ex
# 10.1.2.26
# 10.7.101.26

# ups.chmel.ex
# 10.1.2.28
# 10.7.101.28

# ocs.chmel.ex
# 10.1.2.27
# 10.7.101.27

# monitoring
# 10.1.2.29
# 10.7.101.29

# ops-desktop1
# 10.1.3.32
# 10.7.101.32

# ops-desktop2
# 10.1.3.33
# 10.7.101.33

# insider
# 10.1.3.34
# 10.7.101.34

# admin1
# 10.1.4.46
# 10.7.101.46

# admin2
# 10.1.4.47
# 10.7.101.47

# admin3
# 10.1.4.48
# 10.7.101.48

# admin4
# 10.1.4.49
# 10.7.101.49

# desktop1
# 10.1.4.42
# 10.7.101.42

# desktop2
# 10.1.4.43
# 10.7.101.43

# desktop3
# 10.1.4.44
# 10.7.101.44

# desktop4
# 10.1.4.45
# 10.7.101.45

# CISCO ASA
# 9.66.1.2

# Global Gateway
# 9.66.1.1

# Flow Capture Interface
# 4.122.55.254

# GLOBAL ======================
# red-team{1-6}
# 4.122.55.111-116
# 10.7.100.111-116

# red-team7
# 4.122.55.117
# 10.7.100.117

# global-web
# 4.122.55.2
# 10.7.100.2

# global-dns
# 4.122.55.3
# 10.7.100.3

# global-mail
# 4.122.55.4
# 10.7.100.4

# desktop1
# 4.122.55.5
# 10.7.100.5

# desktop2
# 4.122.55.6
# 10.7.100.6

# global-app
# 4.122.55.7
# 10.7.100.7

# test{1-6}
# 4.122.55.21-26
# 10.7.100.21-26

# nagios-global
# 4.122.55.250
# 10.7.100.250
