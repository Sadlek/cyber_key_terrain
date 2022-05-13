# Date 12.5.2022
# Implementacia algoritmu z clanku
# https://link.springer.com/content/pdf/10.1007/978-3-319-46227-1_42.pdf
# Pouzita transition probability beta bude 0.9, co odpoveda tomu, ze zvycajne sa uskutocni random walk
# Pouzita jumping probability alpha bude 0.85 - ponechany ako v klasickom PageRanku
# vo vysledku budu beta a alpha odhadovane na zaklade feautures of edges
# bipartitny graf - tam by sa dalo zamysliet nad personalized PR pre reccomendation systems

# Pozorovanie zmien alpha pre beta=0.9, pre alpha od 0.6 do 0.95 po dieloch 0.05 sa nic moc nemenilo v Top 10
# pri 0.5 bolo prvych 5 critical, 0.4 a 0.5 boli najlepsie

# Pozorovanie zmien pre beta pri alpha = 0.85, pomerne stabilny vystup
# najlepsi vystup pre 0.8 az 0.95, inak pri odklone nad alebo pod rovnaky o trochu horsi vystup pre Top 10
# P@5 = 80 - 100 %, P@10 = 60 - 70 %

# TODO beta a alpha podla vlastnosti hrany, porovnat zlepsenie
# Mame features: data["sourceIPv4Address"], data["destinationIPv4Address"], data["sourceTransportPort"],
# data["destinationTransportPort"], data["biFlowStartMilliseconds"], data["biFlowEndMilliseconds"],
# data["biFlowEndMilliseconds"] - data["biFlowStartMilliseconds"], data["protocolIdentifier"],
# data["tcpControlBits"], data["packetDeltaCount"], data["octetDeltaCount"]
# pouzijem learning to rank, typ listwise method
# zdroje:
# https://towardsdatascience.com/learning-to-rank-a-complete-guide-to-ranking-using-machine-learning-4c9688d370d4
# https://en.wikipedia.org/wiki/Learning_to_rank
# https://cyber.felk.cvut.cz/theses/papers/471.pdf
# https://cw.fel.cvut.cz/old/_media/courses/xp36vpd/learningtorank.pdf
# https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.299.6152&rep=rep1&type=pdf

# PageRank je funkcia na spocitanie predicted score pre vsetky IP adresy
# jeho vysledna hodnota pre danu IP napr. 4.122.55.3 je vysledkom niektorej z iteracii algoritmu,
# a potom sa uz nemenila, preto je mozne ucit zmeny parametru alpha
# takze, ked sa pocita s funkciou pre vrchol_1, tak pustim PageRank dokym nedostanem vyslednu hodnotu pre vrchol_1
# To tym padom znamena, ze ked chcem ucit algo pre vrchol_2, tak pustim znova tu istu funciu
# tym padom mozem pre kazdy vrchol_n pustit funciu do konca a iba si na konci zobrat hodnotu pre dany parameter
# TODO problem: v ramci PR sa moze hodnota pre vrchol viackrat prepisat,
# ale my zadame vysledok, aky ma byt v danom casovom momente, preto sa to tym vyriesi

# vo vysledku je to clustering
# https://www.shivani-agarwal.net/Publications/2010/mlj10-graphrank-preprint.pdf

# Takze redukcia na Learning To Rank (LTR) je nasledujuca
# input: query q je nepodsatne, je to query-independent approach
# input: n dokumentov D = {d_1, ..., d_n} su IP adresy
# output: pre x_i = (q, d_i) mame true relevance score y_i
# output: nauceny model vypise predicted score s_i = f(x_i) - to bude hodnota PR
# loss function: listwise
# hodi sa Mean Average Precision pre tasky s binarnym vystupom - kriticky/nekriticky

# tym padom dostanem, aka by mala byt vysledna hodnota PageRanku pre dane vstupy
# na zaklade toho mozem spatne spocitat, ake by mali byt medzivysledky a odhadnut hodnotu alpha pre
# jednotlive features hran


import json
from pprint import pprint


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


def tmp_pagerank(ip_flow_filename='data_filtered/data_ipflow_filtered_start.json', alpha=0.85, beta=0.9):
    r = {}
    s = {}
    counter = 0

    with open(ip_flow_filename, 'r') as jsonfile:
        # for each edge = line
        for line in jsonfile.readlines():
            counter += 1
            data = json.loads(line)

            # vertices are only IP addresses
            # timestamp is only temporal for now, incorporate end timestamp and length
            edge_start = data["sourceIPv4Address"]
            edge_end = data["destinationIPv4Address"]
            timestamp = data["biFlowStartMilliseconds"]

            if edge_start not in RESULTS or edge_end not in RESULTS:
                continue

            if edge_start not in r:
                r[edge_start] = 0
            if edge_end not in r:
                r[edge_end] = 0
            if edge_start not in s:
                s[edge_start] = 0
            if edge_end not in s:
                s[edge_end] = 0

            r[edge_start] = r[edge_start] + (1-alpha) # namiesto alpha bude funkcia, kt. berie parametre ako dst_port
            s[edge_start] = s[edge_start] + (1-alpha)
            r[edge_end] = r[edge_end] + s[edge_start]*alpha

            if 0 < beta < 1:
                s[edge_end] = s[edge_end] + s[edge_start]*(1-beta)*alpha
                s[edge_start] = s[edge_start]*beta
            elif beta == 1:
                s[edge_end] = s[edge_end] + s[edge_start]*alpha
                s[edge_start] = 0

            # if counter % 10000 == 0:
            #     print(counter)

    normalize_ranking(r)
    sorted_ranking = {key: value for key, value in sorted(r.items(), key=lambda list_item: list_item[1], reverse=True)}
    with open('output/tmp_output.txt', 'w') as output_file:
        print(sorted_ranking, file=output_file)
        print({key: value for key, value in sorted(s.items(), key=lambda list_item: list_item[1], reverse=True)},
              file=output_file)

    return sorted_ranking


def normalize_ranking(ranking_dict):
    sum_of_rankings = 0
    for key in ranking_dict:
        sum_of_rankings += ranking_dict[key]
    for key in ranking_dict:
        ranking_dict[key] = ranking_dict[key] / sum_of_rankings
    return ranking_dict


def evaluate_results():
    # Tento script spocita vysledky P@5 a P@10 pre rozdielne hodnoty alpha a beta, ktore sa nemenia v ramci algoritmu
    # Najvyssie hodnoty su P@5 = 1.0 a P@10 = 0.7
    # dosiahneme ich pre hodnoty parametrov alpha a beta:
    # 0.4 a 0.9, 0.5 a 0.8, 0.5 a 0.9
    for alpha in range(0, 11):
        for beta in range(1, 11):
            sorted_ranking = tmp_pagerank(alpha=alpha/10, beta=beta/10)
            print("Results for alpha=", alpha/10, " and beta=", beta/10)

            counter = 0
            correct = 0
            incorrect = 0
            for key in sorted_ranking:
                counter += 1
                if key in RESULTS:
                    if RESULTS[key] == 'critical':
                        correct += 1
                    elif RESULTS[key] == 'noncritical':
                        incorrect += 1
                if counter == 5:
                    print("P@5 is ", correct/5)
                if counter == 10:
                    print("P@10 is ", correct/10)
            print()


def alpha_function(dst_port, src_port):
    pass

# TODO mozne dalsie smery zmenit PR na staticky alebo pouzit LTR na time data

# odvodenie vztahu pre vypocet
# hrany budu (u, v, t_1), (u, w, t_2), (u, v, t_3), (w, v , t_4), (w, v, t_5), (v, u, t_6), (u, v, t_7)
# r(u_0) = 0, r(v_0) = 0, r(w_0) = 0, s(u_0) = 0, s(v_0) = 0, s(w_0) = 0

# prva hrana (u, v, t_1)
# r(u_1) = r(u_0) + (1 - alpha(u, v, t_1))
# s(u_1) = s(u_0) + (1 - alpha(u, v, t_1))
# r(v_1) = r(v_0) + s(u_1) * alpha(u, v, t_1) = r(v_0) + (s(u_0) + (1 - alpha(u, v, t_1)) * alpha(u, v, t_1) =
#        = r(v_0) + (s(u_0) + 1) * alpha(u, v, t_1) - alpha^2(u, v, t_1))
# s(v_1) = s(v_0) + s(u_1) * alpha(u, v, t_1) = s(v_0) + (s(u_0) + 1 - alpha(u, v, t_1)) * alpha(u, v, t_1) =
#        = s(v_0) + (s(u_0) + 1) * alpha(u, v, t_1) - alpha^2(u, v, t_1)
# s(u_1) = 0
# r(v_1) = s(v_1)

# druha hrana (u, w, t_2)
# r(u_2) = r(u_1) + (1 - alpha(u, w, t_2)) = r(u_0) + (1 - alpha(u, v, t_1)) + (1 - alpha(u, w, t_2))
# s(u_2) = s(u_1) + (1 - alpha(u, w, t_2)) = s(u_0) + (1 - alpha(u, w, t_2))
# r(w_2) = r(w_1) + s(u_2) * alpha(u, w, t_2) = r(w_0) + (s(u_0) + 1) * alpha(u, w, t_2) - alpha^2(u, w, t_2)
# s(w_2) = s(w_1) + s(u_2) * alpha(u, w, t_2) = s(w_0) + (s(u_0) + 1) * alpha(u, w, t_2) - alpha^2(u, w, t_2)
# s(u_2) = 0

# tretia hrana (u, v, t_3)
# r(u_3) = r(u_2) + (1 - alpha(u, v, t_3)) = r(u_0) + (1 - alpha(u, v, t_1)) + (1 - alpha(u, w, t_2)) + (1 - alpha(u, v, t_3)) =
# s(u_3) = s(u_2) + (1 - alpha(u, v, t_3)) = s(u_0) + (1 - alpha(u, v, t_3))
# r(v_3) = r(v_2) + s(u_3) * alpha(u, v, t_3) =
#        = r(v_0) + (s(u_0) + 1) * alpha(u, v, t_1) - alpha^2(u, v, t_1)) + (s(u_0) + 1) * alpha(u, v, t_3) - alpha^2(u, v, t_3) =
#        = r(v_0) + [s(u_0) + 1] * [alpha(u, v, t_1) + alpha(u, v, t_3)] - [alpha^2(u, v, t_1) + alpha^2(u, v, t_3)]
# s(v_3) = s(v_2) + s(u_3) * alpha(u, v, t_3) =
#        = s(v_0) + (s(u_0) + 1) * alpha(u, v, t_1) - alpha^2(u, v, t_1) + (s(u_0) + 1) * alpha(u, v, t_3) - alpha^2(u, v, t_3) =
#        = s(v_0) + [s(u_0) + 1] * [alpha(u, v, t_1) + alpha(u, v, t_3)] - [alpha^2(u, v, t_1) + alpha^2(u, v, t_3)]
# s(u_3) = 0

# stvrta hrana (w, v , t_4)
# r(w_4) = r(w_3) + (1 - alpha(w, v , t_4)) =
#        = r(w_0) + (s(u_0) + 1) * alpha(u, w, t_2) - alpha^2(u, w, t_2) + (1 - alpha(w, v , t_4))
# s(w_4) = s(w_3) + (1 - alpha(w, v , t_4)) =
#        = s(w_0) + (s(u_0) + 1) * alpha(u, w, t_2) - alpha^2(u, w, t_2) + (1 - alpha(w, v , t_4))
# r(v_4) = r(v_3) + s(w_4) * alpha(w, v , t_4) =
#        = r(v_0) + [s(u_0) + 1] * [alpha(u, v, t_1) + alpha(u, v, t_3)] - [alpha^2(u, v, t_1) + alpha^2(u, v, t_3)] +
#           + [s(w_0) + (s(u_0) + 1) * alpha(u, w, t_2) - alpha^2(u, w, t_2) + (1 - alpha(w, v , t_4))] * alpha(w, v , t_4) =
#        = [alpha(u, v, t_1) + alpha(u, v, t_3)] - [alpha^2(u, v, t_1) + alpha^2(u, v, t_3)] + alpha(u, w, t_2) * alpha(w, v , t_4) -
#           - alpha^2(u, w, t_2) * alpha(w, v , t_4) + alpha(w, v , t_4) - alpha^2(w, v , t_4) =
#        = [alpha(u, v, t_1) + alpha(u, v, t_3) + alpha(w, v , t_4)] - [alpha^2(u, v, t_1) + alpha^2(u, v, t_3) + alpha^2(w, v , t_4)]
#           + alpha(u, w, t_2) * alpha(w, v , t_4) - alpha^2(u, w, t_2) * alpha(w, v , t_4)
# s(v_4) =
# s(w_4) = 0
# takto sa to vyriesit neda, ze budem spatne dopocitavat alpha

# r (u) = r (u) + (1 − α);
# s(u) = s(u) + (1 − α);
# r (v) = r (v) + s(u)α;
# if β ∈ (0, 1) then
# 7 s(v) = s(v) + s(u)(1 − β)α;
# 8 s(u) = s(u)β;
# 9 else if β = 1 then
# 10 s(v) = s(v) + s(u)α;
# 11 s(u) = 0;

# Dalo by sa to naucit lokalne vezmem si vrchol a jeho okolie v case
# https://slidetodoc.com/learning-to-rank-typed-graph-walks-local-and/

# Backup 13.5. clankov,
# https://www.cs.cmu.edu/~einat/webkdd-2007.pdf
# https://dl.acm.org/doi/pdf/10.1145/1060745.1060828
# https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.104.3328&rep=rep1&type=pdf
# https://dl.acm.org/doi/pdf/10.1145/1150402.1150409
# https://dl.acm.org/doi/pdf/10.1145/3269206.3271698
# Mozno by sa na to dal pouzil lokalny pristup
