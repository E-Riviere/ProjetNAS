import random
import yaml
import ipaddress
from Exscript.protocols import Telnet
import multiprocessing
from multiprocessing import shared_memory
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

def get_vrf_name_from_routeur(router_name, vrf_data):
    for (name, vrf) in vrf_data.items():
        if router_name in vrf["CE"]:
            return name
        
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


def get_routeur_bordure(routeur_data,as_data):
    bordure_client=set({})
    bordure_provider=set({})
    for routeur_id , config_routeur in routeur_data.items():
        for conn in config_routeur["interface"].values():
            for routeur_vois in conn.keys():
                if config_routeur["AS_number"]!=routeur_data[routeur_vois]["AS_number"]:
                    if as_data[config_routeur["AS_number"]]["type"]=="client":
                        bordure_client.add(routeur_id)
                    if as_data[config_routeur["AS_number"]]["type"]=="provider":
                        bordure_provider.add(routeur_id)
    return list(bordure_client),list(bordure_provider)

def affiche_erreur(erreurs):
    if erreurs:
        print("\nIncohérences détectées:")
        for erreur in erreurs:
            print(erreur)
    else:
        print("\nAucune incohérence trouvée.")

        
def get_network_to_advivertise_per_router(routeur_data,bordure_client,subnet,connections):
    network_to_advertise={}
    for i in bordure_client:
        visited=[]
        to_visit=[i]
        network_to_advertise[i]=set({})
        while to_visit!=[]:
            rout=to_visit.pop(0)
            for y in subnet:
                if y[0]==rout:
                    network_to_advertise[i].add(subnet[y])
            for k in connections:
                if rout == k[0][0] and routeur_data[k[1][0]]["AS_number"]==routeur_data[i]["AS_number"]:
                    if routeur_data[k[1][0]] not in visited:
                        to_visit.add(routeur_data[k[1][0]])
                elif rout == k[1][0] and routeur_data[k[0][0]]["AS_number"]==routeur_data[i]["AS_number"]:
                    if routeur_data[k[0][0]] not in visited:
                        to_visit.append(routeur_data[k[0][0]])
            visited.append(rout)
    return network_to_advertise
            


def send_ibgp_peers(conn, routeur, config, routeur_data, ips, bordure_provider, address_family):
    for routeur_name, config_routeur in routeur_data.items():
        if config_routeur['AS_number'] == config['AS_number'] and routeur != routeur_name and routeur_name in bordure_provider:
            
            conn.send("exit \r")
            conn.send(f"neighbor {ips[(routeur_name, 'Loopback0')]} remote-as {config['AS_number']}\r")
            conn.send(f"neighbor {ips[(routeur_name, 'Loopback0')]} update-source Loopback0\r")

            conn.send(f"address-family {address_family}\r")
            conn.send(f"neighbor {ips[(routeur_name, 'Loopback0')]} activate\r")
            if address_family == "ipv4":
                conn.send(f"neighbor {ips[(routeur_name, 'Loopback0')]} disable-connected-check\r")
                conn.send(f"neighbor {ips[(routeur_name, 'Loopback0')]} next-hop-self\r")
            if address_family == "vpnv4":
                conn.send(f"neighbor {ips[(routeur_name, 'Loopback0')]} send-community both\r")
            

def configure_interfaces(conn, routeur, config, subnets, ips, connections, as_data, routeur_data, bordure_provider, IGP):
    
    for (r, interface), subnet in subnets.items():
        if r == routeur and subnet != "Aucune plage disponible":
            ipv4_address = ips[(r, interface)]
            conn.send(f"interface {interface}\r")
            if routeur in bordure_provider:
                for (r1, i1), (r2, i2) in connections:
                    
                    voisin, interface_voisin = (None, None)
                    if routeur == r1 and interface == i1:
                        voisin, interface_voisin = r2, i2
                    elif routeur == r2 and interface == i2:
                        voisin, interface_voisin = r1, i1
                    if not voisin:
                        continue
                    
                    if voisin in bordure_client:
                        for name, client in vrf_data.items():
                            if voisin in client['CE']:
                                conn.send(f"ip vrf {name}\r")
                                
                                with mutex_rd:
                                    rd = shm_rd.buf[0] 
                                    shm_rd.buf[0] += 1
                                    conn.send(f"rd {rd}:{rd}\r")
                                conn.send(f"route-target both {client['rt']}\r")
                                for shared in client['sharing']:
                                    conn.send(f"route-target import {vrf_data[shared]['rt']}\r")
                                conn.send(f"interface {interface}\r")
                                conn.send(f"ip vrf forwarding {name}\r")
                    
            conn.send(f"ip address {ipv4_address} {ipaddress.IPv4Network(subnet).netmask}\r")
            conn.send("no shutdown\r")
            if IGP == "OSPF":
                if interface == 'Loopback0':
                    conn.send("ip ospf 2 area 0\r")
                else:
                    for (r1, i1), (r2, i2) in connections:
                        if (routeur, interface) in [(r1, i1), (r2, i2)]:
                            voisin = r2 if routeur == r1 else r1
                            if routeur_data[voisin]['AS_number'] == config['AS_number']:
                                conn.send("ip ospf 2 area 0\r")

def configure_ospf(conn, IGP, routeur_id, type_as):
    if IGP == "OSPF":
        conn.send("router ospf 2\r")
        conn.send(f"router-id {routeur_id}\r")
        if type_as == 'provider':
            conn.send("mpls ldp autoconfig area 0\r")
        conn.send("exit\r")

def configure_mpls(conn):
    time.sleep(1)
    conn.send("mpls ip\r")
    conn.send("mpls label protocol ldp\r")

def configure_bgp_ibgp(conn, routeur, config, routeur_data, ips, bordure_provider, routeur_id, type_as):
    conn.send(f"router bgp {config['AS_number']}\r")
    conn.send(f"bgp router-id {routeur_id}\r")
    
    if type_as == 'client':
        conn.send("address-family ipv4 unicast\r")
        send_ibgp_peers(conn, routeur, config, routeur_data, ips, bordure_provider, address_family="ipv4")
    elif routeur in bordure_provider:
        for af in ["vpnv4"]:
            conn.send(f"address-family {af}\r")
            send_ibgp_peers(conn, routeur, config, routeur_data, ips, bordure_provider, address_family="vpnv4" if af == "vpnv4" else "ipv4")
        conn.send("end\r")

def configure_bgp_ebgp(conn, routeur, config, connections, ips, routeur_data, bordure_client, bordure_provider, vrf_data, type_as,shm_name):
    shm_rd = shared_memory.SharedMemory(shm_name)
    eBGP = False
    for (r1, i1), (r2, i2) in connections:
        voisin, interface_voisin = (None, None)
        if routeur == r1:
            voisin, interface_voisin = r2, i2
        elif routeur == r2:
            voisin, interface_voisin = r1, i1
        if not voisin:
            continue
        if type_as == 'client' and routeur_data[voisin]['AS_number'] != config['AS_number']:
            eBGP = True
            conn.send(f"neighbor {ips[(voisin, interface_voisin)]} remote-as {routeur_data[voisin]['AS_number']}\r")
            conn.send(f"neighbor {ips[(voisin, interface_voisin)]} activate\r")
            conn.send(f"neighbor {ips[(voisin, interface_voisin)]} next-hop-self\r")
            if routeur in bordure_client:
                conn.send(f"neighbor {ips[(voisin, interface_voisin)]} allowas-in\r")
        elif routeur in bordure_provider and voisin in bordure_client:
            conn.send("end\r")


            if routeur_data[voisin]['AS_number'] != config['AS_number']:
                eBGP = True
                conn.send("config t\r")
                conn.send(f"router bgp {config['AS_number']}\r")
                vrf = get_vrf_name_from_routeur(voisin,vrf_data)
                if vrf:
                    conn.send(f"address-family ipv4 vrf {vrf}\r")
                else:
                    print(f"Error no vrf find for {voisin}")
                conn.send(f"neighbor {ips[(voisin, interface_voisin)]} remote-as {routeur_data[voisin]['AS_number']}\r")
                conn.send(f"neighbor {ips[(voisin, interface_voisin)]} activate\r")
                conn.send(f"neighbor {ips[(voisin, interface_voisin)]} next-hop-self\r")
    shm_rd.close()
    return eBGP

def advertise_networks(conn, eBGP, subnets, as_data, config, type_as, routeur, bordure_provider):
    if not eBGP:
        return
    time.sleep(1)
    advertised_networks = set()
    for subnet in subnets.values():
        if subnet == "Aucune plage disponible" or subnet in advertised_networks:
            continue
        prefixlen = ipaddress.IPv4Network(subnet).prefixlen
        if type_as == 'client' and prefixlen != 32 or routeur in bordure_provider and prefixlen != 128:
            if get_AS_number_from_subnet(subnet, as_data) == config['AS_number']:
                advertised_networks.add(subnet)
                conn.send(f"network {ipaddress.IPv4Network(subnet).network_address} mask {ipaddress.IPv4Network(subnet).netmask}\r")
def configure_routeur_telnet(routeur, config, subnets, ips, connections, as_data, routeur_data, bordure_client, bordure_provider, vrf_data,shm_name):
    IGP = as_data[config['AS_number']]['igp']
    host = "localhost"
    port = config['port_telnet']

    conn = Telnet()
    conn.connect(host, port)
    conn.send("\rconfigure terminal\r")

    configure_interfaces(conn, routeur, config, subnets, ips, connections, as_data, routeur_data, bordure_provider, IGP)
    conn.send("exit\r")

    routeur_num = int(config['port_telnet'])
    routeur_id = f"{routeur_num//(256*256*256)+1}.{routeur_num% (256*256*256) // (256*256)}.{routeur_num % (256*256) // 256}.{routeur_num%256}"
    type_as = as_data[config['AS_number']]['type']
    configure_ospf(conn, IGP, routeur_id,type_as)
    if type_as == 'provider':
        configure_mpls(conn)
    
    configure_bgp_ibgp(conn, routeur, config, routeur_data, ips, bordure_provider, routeur_id, type_as)

    eBGP = configure_bgp_ebgp(conn, routeur, config, connections, ips, routeur_data, bordure_client, bordure_provider, vrf_data, type_as,shm_name)
    advertise_networks(conn, eBGP, subnets, as_data, config, type_as, routeur, bordure_provider)
    time.sleep(1)
    conn.send("end\r")
    conn.send(f"ping {ips[(routeur, 'Loopback0')]}\r")
    conn.waitfor("Sending 5, 100-byte ICMP Echos")
    print(f"Configuration de {routeur} terminée.")




    

    

if __name__ == "__main__":
    as_file = "as.yml"
    routeur_file = "routeur.yml"
    vrf_file = "vrf.yml"
    try:

        shm_rd = shared_memory.SharedMemory(create=True, size=1)
        shm_rd.buf[0] = 0

        as_data = load_yaml(as_file)
        routeur_data = load_yaml(routeur_file)
        vrf_data = load_yaml(vrf_file)

        connections, erreurs = get_connections(routeur_data)
        mutex_rd = multiprocessing.Lock()
        
        subnets,ips = get_subnets_and_router_ips(connections, routeur_data, as_data)
        affiche_connexion(connections, subnets, routeur_data)
        affiche_erreur(erreurs)
        check_for_duplicates_ips(subnets, ips)
        bordure_client,bordure_provider=get_routeur_bordure(routeur_data,as_data)
        network_to_advertise=get_network_to_advivertise_per_router(routeur_data,bordure_client,subnets,connections)

        with multiprocessing.Pool() as pool:
            pool.starmap(configure_routeur_telnet, [(routeur, config, subnets, ips, connections, as_data, routeur_data, bordure_client, bordure_provider,vrf_data,shm_rd.name) for routeur, config in routeur_data.items()])
        shm_rd.close()
        shm_rd.unlink()

    except FileNotFoundError:
        print(f"Erreur : Fichier non trouvé.")
