from sklearn import tree
import json
import array
from pprint import pprint
from sklearn import preprocessing, metrics, svm
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler


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
                          data["biFlowStartMilliseconds"],
                          data["biFlowEndMilliseconds"],
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
    # for i in range(len(test_target)):
    #     if clf.predict([test_array[i]]) != test_target[i]:
    #         mistakes += 1
    #         print("i", i)
    #         print("clf.predict(test_array[" + str(i) + "])", clf.predict([test_array[i]]))
    #         print("test_target[" + str(i) + "]", test_target[i])
    # return clf.predict([test_array[1]]), test_target[1]

    # Decision Tree má 37 chýb na nejakých viac ako 43 000 testovacích položkách, čo je
    # menej ako 1%
    print("Decision Tree mistakes", mistakes)
    predicted_results = clf.predict(test_array)
    print("Accuracy:", metrics.accuracy_score(test_target, predicted_results))
    cm = metrics.confusion_matrix(test_target, predicted_results)
    print(cm)

    # Naive Bayes classifier
    # https://www.datacamp.com/community/tutorials/naive-bayes-scikit-learn
    gnb = GaussianNB()
    gnb.fit(training_array, training_target)
    predicted_results = gnb.predict(test_array)
    print("Accuracy:", metrics.accuracy_score(test_target, predicted_results))
    cm = metrics.confusion_matrix(test_target, predicted_results)
    print(cm)

    # mistakes = 0
    # # for i in range(len(test_target)):
    # #     if gnb.predict([test_array[i]]) != test_target[i]:
    # #         mistakes += 1
    # #         print("i", i)
    # #         print("gnb.predict(test_array[" + str(i) + "])", gnb.predict([test_array[i]]))
    # #         print("test_target[" + str(i) + "]", test_target[i])
    # print("Naive Bayes mistakes", mistakes)

    # Logistic regression
    print("Logistic Regression")
    logisticRegr = LogisticRegression()
    logisticRegr.fit(training_array, training_target)
    predicted_results = logisticRegr.predict(test_array)
    print("Accuracy:", metrics.accuracy_score(test_target, predicted_results))
    cm = metrics.confusion_matrix(test_target, predicted_results)
    print(cm)

    # kNN classifier
    print("kNN")
    knn = KNeighborsClassifier(n_neighbors=5)
    knn.fit(training_array, training_target)
    predicted_results = knn.predict(test_array)
    print("Accuracy:", metrics.accuracy_score(test_target, predicted_results))
    cm = metrics.confusion_matrix(test_target, predicted_results)
    print(cm)

    # SVM
    print("SVM")
    clf = svm.SVC(kernel="linear")
    clf.fit(training_array[0:1000], training_target[0:1000])
    predicted_results = clf.predict(test_array)
    print("Accuracy:", metrics.accuracy_score(test_target, predicted_results))
    cm = metrics.confusion_matrix(test_target, predicted_results)
    print(cm)

    # print("SVM")
    # clf = svm.SVC(kernel="linear")
    # clf.fit(test_array[0:1000], test_target[0:1000])
    # predicted_results = clf.predict(training_array)
    # print("Accuracy:", metrics.accuracy_score(training_target, predicted_results))
    # cm = metrics.confusion_matrix(training_target, predicted_results)
    # print(cm)

    # deep neural network multilayer perceptron
    sc_X = StandardScaler()
    X_trainscaled = sc_X.fit_transform(training_array[0:1000])
    X_testscaled = sc_X.transform(test_array)

    clf = MLPClassifier(hidden_layer_sizes=(256, 128, 64, 32),
                        activation="relu", random_state=1)
    clf.fit(X_trainscaled, training_target[0:1000])
    predicted_results = clf.predict(X_testscaled)
    print("Accuracy:", metrics.accuracy_score(test_target, predicted_results))
    cm = metrics.confusion_matrix(test_target, predicted_results)
    print(cm)

    # sc_X = StandardScaler()
    # X_trainscaled = sc_X.fit_transform(test_array[0:1000])
    # X_testscaled = sc_X.transform(training_array)
    #
    # clf = MLPClassifier(hidden_layer_sizes=(256, 128, 64, 32),
    #                     activation="relu", random_state=1)
    # clf.fit(X_trainscaled, test_target[0:1000])
    # predicted_results = clf.predict(X_testscaled)
    # print("Accuracy:", metrics.accuracy_score(training_target, predicted_results))
    # cm = metrics.confusion_matrix(training_target, predicted_results)
    # print(cm)

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

# Decision Tree
# Accuracy: 0.9996105651387075
# [[   67     0     0     0     0     0     0     0     0     0     0     0      0     0     0]
#  [    0  1562     0     0     0     0     0     0     0     0     0     0      0     0     0]
#  [    0     0  2391     0     0     0     0     0     0     0     0     0      0     0     0]
#  [    0     0     0   203     0     1     0     0     0     0     0     0      0     0     0]
#  [    0     0     0     0    80     0     0     0     0     0     0     0      0     0     0]
#  [    0     0     0     0     0  7191     0     0     0     0     0     0      0     0     0]
#  [    0     0     0     0     0     0   330     0     0     0     0     0      0     0     0]
#  [    0     0     0     1     0     0     0   440     0     0     0     0      0     0     0]
#  [    0     0     0     0     0     0     0     0    95     0     0     0      0     0     0]
#  [    0     0     0     0     0     0     0     0     0   830     0     0      0     0     0]
#  [    0     0     0     0     0     0     0     0     0     0   218     0      0     0     0]
#  [    0     0     0     0     0     0     0     0     0     0     0   132      0     0     0]
#  [    0     0     0     0     0    15     0     0     0     0     0     0  29201     0     0]
#  [    0     0     0     0     0     0     0     0     0     0     0     0      0    20     0]
#  [    0     0     0     0     0     0     0     0     0     0     0     0      0     0   876]]

# Naive Bayes
# Accuracy: 0.791446177811376
# [[   37     0     0     0     0     0     0     0    19     0     0     0      0    11     0]
#  [    0   284     0     0     0   325    40     0     0     0   162     0    692     0    59]
#  [    0     0  2391     0     0     0     0     0     0     0     0     0      0     0     0]
#  [    0     0     0   204     0     0     0     0     0     0     0     0      0     0     0]
#  [    0     0     0     0    70     3     0     0     7     0     0     0      0     0     0]
#  [    0     0  1064   452     0  5609     0     0     0     0     0     0     66     0     0]
#  [    0     0     0     0     0     0   322     0     0     0     8     0      0     0     0]
#  [    0    13     0   202     0     1     0   159     0     0     0     0     66     0     0]
#  [   51     0     0     0     0     0     0     0    25     0     0     0      0    19     0]
#  [    0     0     0     0     0     0     0     0     0   222     0   608      0     0     0]
#  [    0     0     0     0     0     0    58     0     0     0   160     0      0     0     0]
#  [   53     0     0     0     0     0     0     0     0     0     0    59      0    20     0]
#  [    0    45    97     0    39  4243   128   178     0     1    40     0  24213     0   232]
#  [    0     0     0     0     0     0     0     0     0     0     0     0      0    20     0]
#  [    0     2     0     0     0     0     0   100     0     0     0     0      0     0   774]]

# Logistic Regression
# Accuracy: 0.682770943577761
# [[    0     0    46     0     0     0     0     0     0     0     0     0     21     0     0]
#  [    0     0     0     0     0     0     0     0     0     0     0     0   1383     0   179]
#  [    0     0   244     0     0     0     0     0     0     1     0     0   2146     0     0]
#  [    0     0     0     0     0     0     0     0     0     0     0     0    204     0     0]
#  [    0     0    25     0     0     0     0     0     0     1     0     0     54     0     0]
#  [    0     0   228     0     0     0     0     0     0     0     0     0   6963     0     0]
#  [    0     0     0     0     0     0     0     0     0     0     0     0    330     0     0]
#  [    0     0     0     0     0     0     0     0     0     0     0     0    441     0     0]
#  [    0     0    63     0     0     0     0     0     0     0     0     0     32     0     0]
#  [    0     0    88     0     0     0     0     0     0     0     0     0    742     0     0]
#  [    0     0     0     0     0     0     0     0     0     0     0     0    218     0     0]
#  [    0     0    43     0     0     0     0     0     0     0     0     0     89     0     0]
#  [    0     0    10     0     0     0     0     0     0     1     0     0  28936     0   269]
#  [    0     0     0     0     0     0     0     0     0     0     0     0     20     0     0]
#  [    0     0     0     0     0     0     0     0     0     0     0     0    251     0   625]]

# kNN
# Accuracy: 0.8678670423567681
# [[   23     0     1     0     0     2     0     0     0     3    20     0      9     9     0     0]
#  [    0   786     1     0     0   116     0     0     1     0     0     0      0   628     0    30]
#  [    3     0  1209     0     9  1056     0     0     0     2     0     0      1   105     0     6]
#  [    0     0     0   203     0     1     0     0     0     0     0     0      0     0     0     0]
#  [    0     2    29     0     5    43     0     0     0     0     0     0      1     0     0     0]
#  [    1   605   409     0   128  5313    15     0     0     0     0     0      1   719     0     0]
#  [    0     0     0     0     0     0     0     0     0     0     0     0      0     0     0     0]
#  [    0     0     0     0     0     0     0   322     0     0     0     0      0     8     0     0]
#  [    0     9     1     0     0    20     0     0   341     0     0     0      0    70     0     0]
#  [   12     0     6     0     0     5     0     0     0    20    31     0     18     3     0     0]
#  [   22     0   508     0     0     8     0     0     0     2   253     0     21    14     2     0]
#  [    0     0     0     0     0     0     0     0     0     0     0   218      0     0     0     0]
#  [   11     0     1     0     0     6     0     0     0     0    11     0     59    44     0     0]
#  [    1   262    19    13     0   501     0     0     4     0     0     0      0 28324     0    92]
#  [    3     0     2     0     0     2     0     0     0     0     0     0      0    13     0     0]
#  [    0     6     0     0     0     0     0     0    59     0     0     0      0     2     0   809]]

# SVM - trained on 1000 items
# Accuracy: 0.8580853549584221
# [[   44     0     0     0     0     0     0     0     6     7     0     9      0     1     0]
#  [    0   573     0     0     0   324     0     1     0     0     0     0    664     0     0]
#  [    0     0  1509     0     0   768     0     0     0     0     0     1    113     0     0]
#  [    0     0     0   204     0     0     0     0     0     0     0     0      0     0     0]
#  [   28     0     0     0     0    19     0     0     0     3     0    30      0     0     0]
#  [   19     6   264   163     0  6732     0     0     7     0     0     0      0     0     0]
#  [    0     0     0     0     0     0   197     0     0     0     6     0    127     0     0]
#  [    0     0     0     0     0   202     0     1     0     0     0     0    238     0     0]
#  [   62     0     0     0     0     0     0     0     9    19     0     4      0     1     0]
#  [   51     0   492     0     0     0     0     0     0   161     0   126      0     0     0]
#  [    0     0     0     0     0     0     0     0     0     0   160     0     58     0     0]
#  [   23     0     0     0     0     0     0     0    17    22     0    69      0     1     0]
#  [    0   493    53   800     0   315     7     2     0     1     0     6  27019     0   520]
#  [    0     0     0     0     0     0     0     0    14     0     0     0      0     6     0]
#  [    0     0     0     0     0     0     0    38     0     0     0     0     64     0   774]]

# MLP - neural network
# Accuracy: 0.8347421712138914
# [[   10     0    53     0     0     4     0     0     0     0     0     0      0     0     0]
#  [    0   242     0     0     0   413     0    90     0     0     0     0    733     0    84]
#  [   47     0  1571     0     0   706     0     0     0     0     0     0     67     0     0]
#  [    0    71     0    10     0     1     0    83     0     0     0     0     39     0     0]
#  [    0     0    35     0     0    45     0     0     0     0     0     0      0     0     0]
#  [   28   154   458    17     0  6194     0   166     0     0     0     0    174     0     0]
#  [    0     0     0     0     0     1     0     0     0     0     0     0    329     0     0]
#  [    0    70     0     0     0     0     0    91     0     0     0     0    280     0     0]
#  [   13     0    62     0     0    20     0     0     0     0     0     0      0     0     0]
#  [   40     0   676     0     0    15     0     0     0    99     0     0      0     0     0]
#  [    0     0     0     0     0    77     0    83     0     0     0     0     58     0     0]
#  [    0     0    42     0     0    49     0     0     0    10     0     0     31     0     0]
#  [    0     8    26     0     0  1344     0     0     0     0     0     3  27610     0   225]
#  [    0     0     9     0     0    11     0     0     0     0     0     0      0     0     0]
#  [    0     0     0     0     0   114     0    48     0     0     0     0    102     0   612]]

# 1.) Klasifikator klasifikuje typy devices
# 2.) Podla Page Ranku sa urcia najdolezitejsie zariadenia, tu global-web a global-dns
# 3.) Podla link prediction sa predpovie, ake zavislosti sa v budcnosti vytvoria - tie su neorientovane,
# pokial node zvykne odpovedat na prichadzajuce spojenia alebo vysielat spojenia, tak dame smer, inak nechame
# neorientovanu hranu

# Do Netboxu dokážem dať devices, device types, IP addreses, IP Ranges, ASN
# manufacturers, ak by sa použil OS fingerprinting od Martina

# TODO vytvorit strukturu siete podľa IP adries
# dajú sa použiť aj dependencies a communication
# DNS má suverejne najviac komunikácie
# z Neo4j - centrality - importance
# community detection - groups
# link prediction - probability that device will be required in the future

# Na obr. bolo niekoľko clusterov.
# Jeden cluster v hornej časti tvoril admin1, admin2, spolu s nejakými ďalšími IP adresami, napr. Google DNS a neznámymi adresami z MU, prípadne mimo.
# Cluster vľavo dole tvoril globálny web spolu so všetkými možnými desktopmi.
# Cluster vpravo dole tvorilo globálne DNS spolu s lokálnymi DNSkami.
# Malý cluster vpravo dole, ale trochu vyššie tvoril z nejakého dôvodu globálny desktop1 spolu s lokálnymi mailservermi BTs. Mailservery boli potom slabšími hranami naviazané na DNSka jednotlivých BTs.
# Podobne to vyzeralo aj pri väčších dátach.
#
# Druhá vizualizácia:
# BT1 Mail server - komunikoval s globálnym desktop1 a s globálnym DNS.
# BT1 DNS server - komunikoval s globálnym desktop1 a s globálnym DNS.
# BT1 web server - komunikoval s globálnym desktop1 a s jedným strojom od Microsoftu.
# BT1 DC server - komunikoval s IP adresami Microsoft korporácie. ASN:8075. Zriedkavo sa našiel niekto ďalší, ako napr. Akamai Technologies pre cloud.
# BT1 File server - komunikoval s adresami od Microsoftu, Akamai Technologies (cloud), Fastly (content delivery network).
# BT1 backup server - s Microsoft adresami.
# BT1 menu server - s adresami mimo MU a adminom3.
# BT1 DB server - s adresami mimo MU a DNS.
# BT1 ocs - s global app, global DNS a adresami, kt. nepatrili na cviko.
# BT1 ups - iba s DNS.
# BT1 monitoring - s nagios-global, globálnymi desktopmi, globálnym webom, global dns, globálny mail.
# Globálny DNS komunikoval so všetkými.
#
#
# =====================
# Komunikácia s Microsoftom sa dá ohaliť na základe ASN 8075 v tokoch - stroje s nainštalovaným Microsoftom.
# DNS server na základe portu 53. Ďalej protokoly indikujú, aké o aké stroje sa môže jednať: DNS - DNS server, ICMP - mail server, ...
# Vytvoriť dataset - trénovací a testovací + nainštalovať pythonovskú knižnicu.
