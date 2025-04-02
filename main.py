import yaml
import ipaddress
from Exscript.protocols import Telnet
import multiprocessing
import time


def load_yaml(filename):
    with open(filename, 'r') as file:
        return yaml.safe_load(file)


def get_connections(routeur_data):
    connections = []
    erreur = []

    for routeur, config in routeur_data.items():
        for interface, voisin in config.get('interface', {}).items():
            for routeur_voisin, interface_voisin in voisin.items():
                connection = tuple(sorted([(routeur, interface), (routeur_voisin, interface_voisin)]))
                if connection not in connections:
                    connections.append(connection)

                config_voisin = routeur_data.get(routeur_voisin, {}).get('interface', {}).get(interface_voisin, {})
                if config_voisin and config_voisin.get(routeur) != interface:
                    erreur.append(f"Incohérence: {routeur} ({interface}) <-> {routeur_voisin} ({interface_voisin})")

    return connections, erreur

def get_AS_number_from_subnet(subnet, as_data):
    for as_id, as_entry in as_data.items():
        for subnet_brut in as_entry.get('plage_adresse', []):
            int_subnet = int(ipaddress.IPv4Network(subnet).network_address)
            int_subnet_brut = int(ipaddress.IPv4Network(subnet_brut).network_address)
            int_mask = int(ipaddress.IPv4Network(subnet_brut).netmask)

            if int_subnet&int_mask == int_subnet_brut&int_mask: 
                return as_id

    return None


def check_for_duplicates_ips(subnets, ips):
    ip_set = set()
    subnet_set = set()

    for interface, ip in ips.items():
        if ip in ip_set:
            return f"Adresse IP dupliquée: {interface} ({ip})"
        ip_set.add(ip)
        print(f"{interface} : {ip}")
    
    for interface, subnet in subnets.items():
        if subnet in subnet_set:
            return f"Sous-réseau dupliqué: {interface} ({subnet})"
        subnet_set.add(subnet)
    

    return None

def get_subnets_and_router_ips(connections, routeur_data, as_data):
    subnets = {}
    interface_ips = {}
    as_subnets = {}
    subnet_routers = {}

    # Initialisation des sous-réseaux par AS
    for as_id, as_entry in as_data.items():
        subnets_brut = as_entry.get('plage_adresse', [])
        as_subnets[as_id] = []
        for subnet_brut in subnets_brut:
            network = ipaddress.IPv4Network(subnet_brut)
            as_subnets[as_id].extend(network.subnets(new_prefix=24)) #trouver le nouveau prefix
        as_subnets[as_id] = iter(as_subnets[as_id])

    tous_les_subnets = set()

    # Attribution des sous-réseaux et des adresses IP
    for (routeur1, interface1), (routeur2, interface2) in connections:
        if (routeur1, interface1) not in subnets and (routeur2, interface2) not in subnets:
            as_id1 = routeur_data[routeur1]['AS_number']
            as_id2 = routeur_data[routeur2]['AS_number']
            as_id = as_id1 if as_id1 <= as_id2 else as_id2
            
            subnet = next(as_subnets[as_id])
            while subnet in tous_les_subnets:
                subnet = next(as_subnets[as_id])
            
            subnets[(routeur1, interface1)] = str(subnet)
            subnets[(routeur2, interface2)] = str(subnet)
            tous_les_subnets.add(subnet)
            subnet_routers[subnet] = set([(routeur1,interface1), (routeur2,interface2)])
        else:
            if (routeur1, interface1) in subnets:
                subnet = ipaddress.IPv4Network(subnets[(routeur1, interface1)])
                subnets[(routeur2, interface2)] = str(subnet)
            else:
                subnet = ipaddress.IPv4Network(subnets[(routeur2, interface2)])
                subnets[(routeur1, interface1)] = str(subnet)
            
            subnet_routers[subnet].add((routeur1,interface1))
            subnet_routers[subnet].add((routeur2,interface2))


    # Attribution des adresses de Loopback
    for as_id in as_data:
        subnet = next(as_subnets[as_id])
        while subnet in tous_les_subnets:
            subnet = next(as_subnets[as_id])
        tous_les_subnets.add(subnet)
        loopback_address = subnet.subnets(new_prefix=32)
        for routeur, config in routeur_data.items():
            if routeur_data[routeur]['AS_number'] == as_id:
                tmp=next(loopback_address)
                subnets[(routeur, 'Loopback0')] = str(tmp)
                interface_ips[(routeur, 'Loopback0')] = str(tmp.network_address)






    # Attribution des adresses IP aux interfaces des routeurs
    for subnet, routers in subnet_routers.items():
        for i, interface in enumerate(routers):
            if interface not in interface_ips:
                interface_ips[interface] = str(subnet[i+1])
    

    
    return subnets, interface_ips


def affiche_connexion(connections, subnets, routeur_data):
    print("Connexions entre routeurs avec sous-réseaux:")
    for (routeur1, interface1), (routeur2, interface2) in connections:
        print(f"{routeur1} ({subnets[(routeur1, interface1)]}) <-> {routeur2} ({subnets[(routeur2, interface2)]})")
    print("\nSous-réseaux attribués pour le loopback par AS :")
    as_visited = set()
    for interface ,subnet in subnets.items():
        if interface[1] == 'Loopback0' and routeur_data[interface[0]]['AS_number'] not in as_visited:
            as_visited.add(routeur_data[interface[0]]['AS_number'])

            print(f"AS : {routeur_data[interface[0]]['AS_number']} : {subnet}")




def affiche_erreur(erreurs):
    if erreurs:
        print("\nIncohérences détectées:")
        for erreur in erreurs:
            print(erreur)
    else:
        print("\nAucune incohérence trouvée.")

def configure_routeur_telnet(routeur, config, subnets, ips, connections, as_data, routeur_data):
        print(routeur[-1])
        IGP = as_data[config['AS_number']]['igp']
        host = "localhost"
        port = config['port_telnet']
        relation_as=as_data[config['AS_number']]["relation"]
        as_relation={}
        for key, values in relation_as.items():
            for value in values:
                as_relation[int(value)] = key
        conn = Telnet()
        conn.connect(host, port)
        conn.send("\rconfigure terminal\r")
        
        #configuration mpls
        conn.send("mpls ip\r")
        conn.send("mpls label protocol ldp\r")
        
        
        for (r, interface), subnet in subnets.items():
            if r == routeur and subnet != "Aucune plage disponible":
                ipv4_address = ips[(r,interface)]
                conn.send(f"interface {interface}\r")
                conn.send(f"ip address {ipv4_address} {ipaddress.IPv4Network(subnet).netmask}\r")
                conn.send("no shutdown\r")
                if IGP == "OSPF" :
                    if interface == 'Loopback0':
                        conn.send(f"ip ospf 2 area 0\r")
                    else:
                        for (routeur1, interface1), (routeur2, interface2) in connections:
                            if routeur == routeur1 and interface == interface1:
                                voisin = routeur2
                                interface_voisin = interface2
                            elif routeur == routeur2 and interface == interface2:
                                voisin = routeur1
                                interface_voisin = interface1
                            else:
                                voisin = None
                                interface_voisin = None
                            if voisin:
                                if routeur_data[voisin]['AS_number'] == config['AS_number']:
                                    conn.send(f"ip ospf 2 area 0\r")

        conn.send("exit\r")
        routeur_num = int(config['port_telnet'])

        routeur_id = f"{routeur_num//(256*256*256)+1}.{routeur_num% (256*256*256) // (256*256)}.{routeur_num % (256*256) // 256}.{routeur_num%256}"
        # Configuration de l'IGP
        if IGP == "OSPF":
            conn.send("router ospf 2\r")
            conn.send(f"router-id {routeur_id} \r")
            conn.send("mpls ldp autoconfig area 0\r")
            conn.send("exit\r")

        #configuration route-map
        time.sleep(1)
        # Configuration BGP
        conn.send(f"router bgp {config['AS_number']}\r")
        conn.send(f"bgp router-id {routeur_id}\r")
        conn.send("address-family ipv4 unicast\r")
        for routeur_id , config_routeur in routeur_data.items():
            if config_routeur['AS_number'] == config['AS_number'] and routeur != routeur_id:
                conn.send(f"neighbor {ips[(routeur_id, 'Loopback0')]} remote-as {config['AS_number']}\r")
                conn.send(f"neighbor {ips[(routeur_id, 'Loopback0')]} update-source Loopback0\r")
                conn.send(f"neighbor {ips[(routeur_id, 'Loopback0')]} disable-connected-check\r")
                conn.send(f"neighbor {ips[(routeur_id, 'Loopback0')]} next-hop-self\r")
                conn.send(f"neighbor {ips[(routeur_id, 'Loopback0')]} activate\r")
        eBGP = False
        time.sleep(0.5)
        for (routeur1, interface1), (routeur2, interface2) in connections:
            
            if routeur == routeur1:
                voisin = routeur2
                interface_voisin = interface2

            elif routeur == routeur2:
                voisin = routeur1
                interface_voisin = interface1
            else:
                voisin = None
                interface_voisin = None
            if voisin:
                if routeur_data[voisin]['AS_number'] != config['AS_number']:
                    eBGP = True
                    conn.send(f"neighbor {ips[(voisin, interface_voisin)]} remote-as {routeur_data[voisin]['AS_number']}\r")
                    conn.send(f"neighbor {ips[(voisin, interface_voisin)]} activate\r")
                    conn.send(f"neighbor {ips[(voisin, interface_voisin)]} next-hop-self\r")
                

                    
        time.sleep(0.5)
        networks_to_advertise = "all"
        advertised_networks = set()
        if eBGP:
            if networks_to_advertise == "all":
                for subnet in subnets.values():
                    
                    if subnet != "Aucune plage disponible" and ipaddress.IPv4Network(subnet).prefixlen != 128 and subnet not in advertised_networks:
                        if get_AS_number_from_subnet(subnet, as_data) == config['AS_number']:
                            advertised_networks.add(subnet)
                            conn.send(f"network {ipaddress.IPv4Network(subnet).network_address} mask {ipaddress.IPv4Network(subnet).netmask}\r")


            else:
                for subnet in networks_to_advertise:
                    conn.send(f"network {ipaddress.IPv4Network(subnet).network_address} mask {ipaddress.IPv4Network(subnet).netmask}\r")
                
        conn.send("end\r")


        conn.send(f"ping {ips[(routeur, 'Loopback0')]}\r")
        conn.waitfor("Sending 5, 100-byte ICMP Echos")

        print(f"Configuration de {routeur} terminée.")


        




    

    

if __name__ == "__main__":
    as_file = "as.yml"
    routeur_file = "routeur.yml"
    try:
        as_data = load_yaml(as_file)
        routeur_data = load_yaml(routeur_file)

        connections, erreurs = get_connections(routeur_data)
        
        subnets,ips = get_subnets_and_router_ips(connections, routeur_data, as_data)
        affiche_connexion(connections, subnets, routeur_data)
        affiche_erreur(erreurs)
        check_for_duplicates_ips(subnets, ips)

        with multiprocessing.Pool() as pool:
            pool.starmap(configure_routeur_telnet, [(routeur, config, subnets, ips, connections, as_data, routeur_data) for routeur, config in routeur_data.items()])



    except FileNotFoundError:
        print(f"Erreur : Fichier non trouvé.")
