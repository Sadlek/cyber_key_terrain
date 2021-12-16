import json


# TODO
# "10.7.101.12" == "9.66.11.12"
def filter_ip(ip_address):
    output_lines = []
    with open(f'data_{ip_address}.json', 'w') as output_file:
        with open('data/data.json', 'r') as jsonfile:
            for line in jsonfile.readlines():
                data = json.loads(line)
                if data["destinationIPv4Address"] == ip_address or data["sourceIPv4Address"] == ip_address:
                    output_lines.append(data)
        json.dump(output_lines, fp=output_file)
