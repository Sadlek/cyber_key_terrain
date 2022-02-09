from sklearn import tree
import json
import array
from pprint import pprint
from sklearn import preprocessing


NAMES = {'9.66.11.12': 'mail server',
         '9.66.11.13': 'DNS server',
         '9.66.11.14': 'web server',
         '10.1.2.22': 'dc',
         '10.1.2.23': 'file server',
         '10.1.2.24': 'backup server',
         '10.1.2.25': 'menu server',
         '10.1.2.26': 'DB server',
         '10.1.2.28': 'ups',
         '10.1.2.27': 'ocs',
         '10.1.2.29': 'monitoring',
         '10.1.3.32': 'desktop',
         '10.1.3.33': 'desktop',
         '10.1.4.46': 'admin',
         '10.1.4.47': 'admin',
         '10.1.4.48': 'admin',
         '10.1.4.49': 'admin',
         '10.1.4.42': 'desktop',
         '10.1.4.43': 'desktop',
         '10.1.4.44': 'desktop',
         '10.1.4.45': 'desktop',
         '9.66.1.2': 'cisco_asa',
         '9.66.1.1': 'global_gateway',
         '4.122.55.254': 'flow_capture_interface',
         # '4.122.55.111': 'PC',  # redteam to 111-116
         # red-team7         # 4.122.55.117
         '4.122.55.2': 'web server',
         '4.122.55.3': 'DNS server',
         '4.122.55.4': 'mail server',
         '4.122.55.5': 'desktop',
         '4.122.55.6': 'desktop',
         '4.122.55.7': 'app server',
         # test{1-6}  # 4.122.55.21-26
         '4.122.55.250': 'nagios'
         }


def prepare_sets(ip_flow_filename='data_filtered/data_ipflow_filtered_start.json'):
    # Function prepares training and test sets
    # Mainly extended flow was skipped
    # Structure of one item in array is denoted by keys from data
    training_array = []
    test_array = []
    training_target = []
    test_target = []
    counter = 0
    treshold = 174614
    set_of_ip_addresses = set()
    with open(ip_flow_filename, 'r') as jsonfile:
        for line in jsonfile.readlines():
            data = json.loads(line)
            set_of_ip_addresses.add(data["sourceIPv4Address"])
            set_of_ip_addresses.add(data["destinationIPv4Address"])

    print("encoding")
    le = preprocessing.LabelEncoder()
    le.fit(list(set_of_ip_addresses))

    with open(ip_flow_filename, 'r') as jsonfile:
        for line in jsonfile.readlines():
            counter += 1
            print("counter", counter)
            data = json.loads(line)
            # print(data)

            array_item = [
                          # data["biFlowStartMilliseconds"],
                          # data["biFlowEndMilliseconds"],
                          le.transform([data["sourceIPv4Address"]]),
                          data["sourceTransportPort"] if "sourceTransportPort" in data else 0,
                          le.transform([data["destinationIPv4Address"]]),
                          data["destinationTransportPort"] if "destinationTransportPort" in data else 0,
                          data["protocolIdentifier"],
                          data["bgpDestinationAsNumber"],
                          data["bgpSourceAsNumber"]]  #,
                          # data["applicationName"] if "applicationName" in data else None]
                          # data["exercise_dst_ipv4_segment"]] # vyhodene, pretoze v realnom svete nebude

            if counter <= treshold:
                training_array.append(array_item)

                # GROUND TRUTH
                if data["sourceIPv4Address"] in NAMES:
                    training_target.append(NAMES[data["sourceIPv4Address"]])
                else:
                    training_target.append("other")
            else:
                test_array.append(array_item)

                # GROUND TRUTH
                if data["sourceIPv4Address"] in NAMES:
                    test_target.append(NAMES[data["sourceIPv4Address"]])
                else:
                    test_target.append("other")

    # print("training array")
    # print(training_array)
    # print("test array")
    # print(test_array)
    # print("training target")
    # print(training_target)
    # print("test target")
    # print(test_target)


    # DT ========================================
    clf = tree.DecisionTreeClassifier()
    clf = clf.fit(training_array, training_target)

    mistakes = 0
    for i in range(len(test_target)):
        if clf.predict([test_array[i]]) != test_target[i]:
            mistakes += 1
            print("i", i)
            print("clf.predict(test_array[" + str(i) + "])", clf.predict([test_array[i]]))
            print("test_target[" + str(i) + "]", test_target[i])
    # return clf.predict([test_array[1]]), test_target[1]

    # Decision Tree má 37 chýb na nejakých viac ako 43 000 testovacích položkách, čo je
    # menej ako 1%
    print("Decision Tree mistakes", mistakes)

    # TODO Naive Bayes classifier
    # https://www.datacamp.com/community/tutorials/naive-bayes-scikit-learn

            # Other possible
            #  "ipClassOfService"
            # "octetDeltaCount": 56, "octetDeltaCount_Rev": 105, "packetDeltaCount": 1, "packetDeltaCount_Rev": 1,
            # "protocolIdentifier": 17, "samplingAlgorithm": 0, "samplingInterval": 0


# mail.firechmel.ex
# 9.66.11.12

# dns.firechmel.ex
# 9.66.11.13

# www.firechmel.ex
# 9.66.11.14

# dc
# 10.1.2.22

# files
# 10.1.2.23

# backup
# 10.1.2.24

# menu
# 10.1.2.25

# db.chmel.ex
# 10.1.2.26

# ups.chmel.ex
# 10.1.2.28

# ocs.chmel.ex - OCS inventory?
# 10.1.2.27

# monitoring
# 10.1.2.29

# ops-desktop1
# 10.1.3.32

# ops-desktop2
# 10.1.3.33

# insider
# 10.1.3.34

# admin1
# 10.1.4.46

# admin2
# 10.1.4.47

# admin3
# 10.1.4.48

# admin4
# 10.1.4.49

# desktop1
# 10.1.4.42

# desktop2
# 10.1.4.43

# desktop3
# 10.1.4.44

# desktop4
# 10.1.4.45

# CISCO ASA
# 9.66.1.2

# Global Gateway
# 9.66.1.1

# Flow Capture Interface
# 4.122.55.254

# GLOBAL ======================
# red-team{1-6}
# 4.122.55.111-116

# red-team7
# 4.122.55.117

# global-web
# 4.122.55.2

# global-dns
# 4.122.55.3

# global-mail
# 4.122.55.4

# desktop1
# 4.122.55.5

# desktop2
# 4.122.55.6

# global-app
# 4.122.55.7

# test{1-6}
# 4.122.55.21-26

# nagios-global
# 4.122.55.250

