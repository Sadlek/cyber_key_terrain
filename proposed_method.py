# 1.) histogram komunikacie podla portov
# 2.) spocitaj PageRank pre komunikaciu na jednotlive porty a oznac critical devices podla tejto komunikacie
# 3.) vezmi device a ostatne IP zo siete, spocitaj Adamic-Adar index a urci dependencies, brat do uvahy aj existujuce
# hrany, cize to nejako upravit
# Evaluation: vyhodnotit na vzorke, kde dokazeme vyhodnotit precision a recall - vysledky
# Evaluation: casove aspekty - time series neberieme do uvahy, takisto ci to stihne spocitat v danom casovom okne
# 3 sa da pouzit aj pre urcenie zavislosti, napr. eshopoveho webserveru

# TODO Problemy: threshold neviem urcit pre porty, IP adresy, ani dependencies
from neo4j import GraphDatabase, basic_auth
from construct_ckt import find_elbow
from pprint import pprint

BOLT = 'bolt://localhost:7687'
DRIVER = GraphDatabase.driver(BOLT, auth=basic_auth("neo4j", "ne04jcrus03"), encrypted=False)
# DRIVER = GraphDatabase.driver(BOLT, auth=basic_auth("neo4j", "Neo4jPas"), encrypted=False)


def determine_dependencies():
    # Vezmi si nejaky subnet alebo siet. V pripade CyberCzechu to bude napr. BT1-BT6 alebo Global, v pripade realnom je
    # to siet MU. Vezmi si komunikaciu vychadzajucu zo skumanej siete/subnetu von a dnu. Vykonaj histogram portov.
    # Spocitaj PageRank a vyber zo zoznamu iba tie, ktore su zo skumanej siete/subnetu + threshold. AA index bude
    # iba k zariadeniam v ramci siete. Zariadenia yvonku siete, ale aj vnutorne sa daju pridat na zaklade priamej
    # komunikacie.
    # Zariadenia vnutorne, kt. priamo komunikovali v ramci skumanej siete - tam funguje AA index O(n^2).
    # Zariadenia B zvonka, s kt. komunikovalo zariadenie A - zanedbame komunikaciu, kt. malo zariadenie B vonku a
    # skusime si pridat zariadenie B do skumanej siete. Teda skumame vzorec A(x, y) = suma u z N(x) prienik
    # (N(y) zo skumanej siete) a potom logaritmus 1/log(pocet N(u)). In fact, cely vzorec pre Adamic Adar upravuje tak,
    # aby fungoval s tym, ze komunikaciu zachytavame na hrane skumanej siete, teda von a dnu. Nezachytime
    # vnutornu komunikaciu a pochopitelne celosvetovu vonkajsiu.
    # Note: je to PageRank na bipartitnom grafe, ale to teraz nebudem uvadzat do clanku. V zasade to znamena, ze
    # strieda hrany medzi dvoma skupinami. Vo vysledku mozeme spocitat PageRank nad vsetkymi datami a iba filtrovat
    # podla toho, kt. skupina nas zaujima. PageRank ma complexity O(n + m)
    with(DRIVER.session()) as session:
        result = session.run("MATCH ()-[r:COMMUNICATES_WITH]->() "
                    "RETURN r.dst_port AS dst_port, COUNT(r.dst_port) AS port_count "
                    "ORDER BY port_count DESC")
        port_list = result.data()
        print(port_list[0:20])

    # TODO threshold nefunguje, zoberiem top ten
    # x, y, value = find_elbow(list(range(0, len(port_list))), [item['port_count'] for item in port_list])
    # print("Elbow x:", x, ", y: ", y, ", value: ", value)

    critical_ip_addresses = {}
    list_of_ip_addresses = []
    for item in port_list[0:5]:
        destination_port = item['dst_port']
        print(destination_port)
        # pri datach z collectoru sa musia dat porty ako string
        with(DRIVER.session()) as session:
            # result = session.run("CALL gds.pageRank.stream({nodeQuery: 'MATCH (n) RETURN id(n) AS id', "
            #                      "relationshipQuery: 'MATCH (ip1:IP_ADDRESS)-[r:COMMUNICATES_WITH]->(ip2:IP_ADDRESS) "
            #                      f"WHERE r.dst_port = \"{destination_port}\" "
            #                      "RETURN DISTINCT id(ip1) AS source, id(ip2) AS target, r.dst_port AS dst_port'}) "
            #                      "YIELD nodeId, score RETURN gds.util.asNode(nodeId).address AS address, score "
            #                      "ORDER BY score DESC")
            result = session.run("CALL gds.pageRank.stream({nodeQuery: 'MATCH (n) RETURN id(n) AS id', "
                                 "relationshipQuery: 'MATCH (ip1:IP_ADDRESS)-[r:COMMUNICATES_WITH]->(ip2:IP_ADDRESS) "
                                 f"WHERE r.dst_port = {destination_port} "
                                 "RETURN DISTINCT id(ip1) AS source, id(ip2) AS target, r.dst_port AS dst_port'}) "
                                 "YIELD nodeId, score RETURN gds.util.asNode(nodeId).address AS address, score "
                                 "ORDER BY score DESC")
            result_for_currrent_port = result.data()[0:30]
            # TODO tu vyfiltrovat zariadenia zo skumanej siete, moze byt kriticke zariadenie aj zvonka siete?
            # Nechcem brat kriticke zariadenia zvonka siete. Dovod: vonkajsie zariadenia maju obrovske mnozstvo
            # komunikacie, kt. nikdy nezmapujeme ako graf a nevieme ani, zatialco u vnutornej partity hoci nezachytavame
            # vnutornu komunikaciu, tak zvycajne vieme odhadnut, co tam bude, napr. ako CIDR pre IP adresy.
            # Vonkajsie neberiem, lebo 3rd party services budu az sprostredkovane zavislosti.
            # Dokazem urcit DNS server.
        print("results for current port")
        print(result_for_currrent_port)
        # MU results
        # filtered_results = [list_item for list_item in result_for_currrent_port
        #                     if list_item['address'].startswith('147.251.')]
        # CyberCzech
        filtered_results = [list_item for list_item in result_for_currrent_port
                            if list_item['address'] in ['9.66.11.12', '9.66.11.13', '9.66.11.14', '10.1.2.22', '10.1.2.23', '10.1.2.24', '10.1.2.25', '10.1.2.26',
            '10.1.2.28', '10.1.2.27', '10.1.2.29', '10.1.3.32', '10.1.3.33', '10.1.3.34', '10.1.4.46', '10.1.4.47',
            '10.1.4.48', '10.1.4.49', '10.1.4.42', '10.1.4.43', '10.1.4.44', '10.1.4.45']]
        print("filtered results")
        print(filtered_results)
        x, y, value = find_elbow(list(range(0, len(filtered_results))),
                                 [list_item['score'] for list_item in filtered_results])
        print("Elbow x:", x, ", y: ", y, ", value: ", value)
        for list_item in filtered_results:
            if list_item['score'] >= y:
                list_of_ip_addresses.append(list_item['address'])
                if destination_port in critical_ip_addresses:
                    critical_ip_addresses[destination_port].append(list_item['address'])
                else:
                    critical_ip_addresses[destination_port] = [list_item['address']]
        print()

    for ip_address in list_of_ip_addresses:
        # neighbors = []
        with (DRIVER.session()) as session:
            result = session.run('MATCH (n:IP_ADDRESS {address: $ip_address}) '
                                 'CALL apoc.neighbors.byhop(n, "COMMUNICATES_WITH", 2) YIELD nodes RETURN nodes',
                                 **{'ip_address': ip_address})
            neighbors = result.data()
            # print("1 hop")
            # pprint(neighbors[0])
            # print("2 hops")
            # pprint(neighbors[1])
        adamic_adar_values = {}
        for first_lvl_neighbor in neighbors[0]['nodes']:
            lp_metrics = adamic_adar_index(ip_address, first_lvl_neighbor['address'])
            adamic_adar_values[first_lvl_neighbor['address']] = lp_metrics['score_aa']

        for snd_level_neighbor in neighbors[1]['nodes']:
            lp_metrics = adamic_adar_index(ip_address, snd_level_neighbor['address'])
            adamic_adar_values[snd_level_neighbor['address']] = lp_metrics['score_aa']
        # najdi susedov x, pre kazde najdi ich susedov, t.j. spocitaj pre x susedov druhej urovne
        # s tymito susedmi druhej urovne zavolaj Adamic Adar index
        # vsetci ostatni maju s x nulovy index
        # pre zariadenia zvonku siete vezmi iba tie, s kt. priamo komunikoval
        # pre zariadenia zvonku neberieme susedov druhej urovne, lebo ich moze byt potencialne velmi vela

        print("First IP: ", ip_address)
        aa_values_sorted = {key: value for key, value in sorted(adamic_adar_values.items(),
                                                                key=lambda list_item: list_item[1], reverse=True)}
        print(aa_values_sorted)
        x, y, value = find_elbow(list(range(0, len(aa_values_sorted.keys()))), list(aa_values_sorted.values()))
        print("Elbow's x: ", x, ", y: ", y, ", value: ", value)
        print()

        counter = 0
        for key in aa_values_sorted:
            value = aa_values_sorted[key]
            if value < y or counter > x:
                break
            else:
                # create_dependency_in_database(first_ip, key, value)
                print("SRC IP: ", ip_address, ", DST IP: ", key, ", value: ", value)
                counter += 1
        print()


def adamic_adar_index(first_ip, second_ip):
    with (DRIVER.session()) as session:
        result = session.run("MATCH (p1:IP_ADDRESS {address: $first_ip}) "
                             "MATCH (p2:IP_ADDRESS {address: $second_ip}) "
                             "RETURN gds.alpha.linkprediction.adamicAdar(p1, p2) AS score_aa",
                             **{'first_ip': first_ip, 'second_ip': second_ip})
        lp_metrics = result.data()[0]
    return lp_metrics

# Vysledky behu na datach v DB:
# criticke device podla PageRank -> depedent device or device, na kt. je critical device dependent
# is.muni.cz -> webserver.ics.muni.cz, pyrrha.fi.muni.cz, muni.islogin.cz, webcentrum-c.ics.muni.cz,
#               maps.dis.ics.muni.cz
# webcentrum-c.ics.muni.cz -> www.muni.cz, is.muni.cz
# ns.muni.cz / ns.ics.muni.cz -> dior.ics.muni.cz / ns2.muni.cz, anxur.fi.muni.cz, aisa.fi.muni.cz, elanor.sci.muni.cz
# ns2.muni.cz / dior.ics.muni.cz -> ns.ics.muni.cz / ns.muni.cz, anxur.fi.muni.cz

# TODO CyberCzechove data daju celkom dobre vysledky, skontrolovat
# https://apps.dtic.mil/sti/pdfs/ADA550373.pdf
