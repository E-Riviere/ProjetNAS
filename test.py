import yaml
import ipaddress
from Exscript.protocols import Telnet

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

def check_for_duplicates_ips(subnets, ips):
    ip_set = set()
    subnet_set = set()

    for interface, ip in ips.items():
        if ip in ip_set:
            return f"Adresse IP dupliquée: {interface} ({ip})"
        ip_set.add(ip)

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
            network = ipaddress.IPv6Network(subnet_brut)
            as_subnets[as_id].extend(network.subnets(new_prefix=64))
        as_subnets[as_id] = iter(as_subnets[as_id])

    tous_les_subnets = set()

    # Attribution des sous-réseaux et des adresses IP
    for (routeur1, interface1), (routeur2, interface2) in connections:
        if (routeur1, interface1) not in subnets and (routeur2, interface2) not in subnets:
            as_id1 = str(routeur_data[routeur1]['AS_number'])
            as_id2 = str(routeur_data[routeur2]['AS_number'])
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
                subnet = ipaddress.IPv6Network(subnets[(routeur1, interface1)])
                subnets[(routeur2, interface2)] = str(subnet)
            else:
                subnet = ipaddress.IPv6Network(subnets[(routeur2, interface2)])
                subnets[(routeur1, interface1)] = str(subnet)
            
            subnet_routers[subnet].add((routeur1,interface1))
            subnet_routers[subnet].add((routeur2,interface2))


    # Attribution des adresses de Loopback
    for as_id in as_data:
        subnet = next(as_subnets[as_id])
        while subnet in tous_les_subnets:
            subnet = next(as_subnets[as_id])
        tous_les_subnets.add(subnet)
        loopback_address = subnet.subnets(new_prefix=128)
        for routeur, config in routeur_data.items():
            if routeur_data[routeur]['AS_number'] == int(as_id):
                subnets[(routeur, 'Loopback0')] = str(next(loopback_address))
                interface_ips[(routeur, 'Loopback0')] = ipaddress.IPv6Network(subnets[(routeur, 'Loopback0')]).network_address






    # Attribution des adresses IP aux interfaces des routeurs
    for subnet, routers in subnet_routers.items():
        for i, interface in enumerate(routers):
            if interface not in interface_ips:
                interface_ips[interface] = str(subnet[i+1])
    

    
    return subnets, interface_ips


def affiche_connexion(connections, subnets):
    print("Connexions entre routeurs avec sous-réseaux:")
    for (routeur1, interface1), (routeur2, interface2) in connections:
        subnet1 = subnets.get((routeur1, interface1), "Non attribué")
        print(f"{routeur1} ({interface1}) <-> {routeur2} ({interface2}): {subnet1}")

def affiche_erreur(erreurs):
    if erreurs:
        print("\nIncohérences détectées:")
        for erreur in erreurs:
            print(erreur)
    else:
        print("\nAucune incohérence trouvée.")

def configure_routeur_telnet(routeur, config, subnets, ips, connections,IGP):
    """Configure les routeurs via Telnet avec Exscript."""
    try:
        host = "localhost"
        port = config['port_telnet']
        conn = Telnet()
        conn.connect(host, port)
        print(f"Connexion à {routeur} sur le port {port}...")
        conn.send("\rconfigure terminal\r")
        conn.send("ipv6 unicast-routing\r")
<<<<<<< HEAD
=======
        if IGP == "OSPF":
            conn.send("ipv6 router ospf 1\r")
            routeurnum = int(routeur[-1])
            conn.send(f"router-id {routeurnum//(256*256*256)}.{routeurnum% (256*256*256) // (256*256)}.{routeurnum % (256*256) // 256}.{routeurnum%256} \r")
            conn.send("exit\r")

        elif IGP == "RIP":
            conn.send("ipv6 router rip RIPng\r")
            conn.send("redistribute connected\r")
            conn.send("exit\r")
        
        
>>>>>>> de7ab5c (Configuration automatique de OSPF et RIP + attribution d'addresse de loopback)
        for (r, interface), subnet in subnets.items():
            if r == routeur and subnet != "Aucune plage disponible":
                ipv6_address = ips[(r,interface)]
                conn.send(f"interface {interface}\r")
                conn.send(f"ipv6 address {ipv6_address}/{ipaddress.IPv6Network(subnet).prefixlen}\r")
<<<<<<< HEAD
                conn.send(f"ipv6 enable\r")
                conn.send("no shutdown\r")
                conn.send("exit\r")
        conn.send("end\r")
        #conn.send("write memory\r\r")
=======
                conn.send("ipv6 enable\r")
                conn.send("no shutdown\r")
                if IGP == "OSPF":
                    conn.send("ipv6 ospf 1 area 0\r")
                elif IGP == "RIP":
                    conn.send("ipv6 rip RIPng enable\r")
        
        
>>>>>>> de7ab5c (Configuration automatique de OSPF et RIP + attribution d'addresse de loopback)
        conn.send("exit\r")
        conn.send("exit\r")
        #conn.send("write memory\r\r")
        # wait for all the command to finish by looking for the prompt of the ping command on loopback
        conn.send(f"ping {ips[(routeur, 'Loopback0')]}\r")
        conn.waitfor("Sending 5, 100-byte ICMP Echos")
        #conn.close()# Faudrait faire ça pour fermer proprement les connections telnet, mais dans ce cas là le programme plante ????

        print(f"Configuration de {routeur} terminée.")

    except Exception as e:
        print(f"Erreur lors de la configuration de {routeur}: {e}")
    


    

if __name__ == "__main__":
    as_file = "as.yml"
    routeur_file = "routeur.yml"
    try:
        as_data = load_yaml(as_file)
        routeur_data = load_yaml(routeur_file)

        connections, erreurs = get_connections(routeur_data)

        subnets,ips = get_subnets_and_router_ips(connections, routeur_data, as_data)
        affiche_connexion(connections, subnets)
        affiche_erreur(erreurs)
        check_for_duplicates_ips(subnets, ips)
        for routeur, config in routeur_data.items():
<<<<<<< HEAD
            configure_routeur_telnet(routeur, config, subnets, ips, connections)
=======
            configure_routeur_telnet(routeur, config, subnets, ips, connections, as_data[str(routeur_data[routeur]['AS_number'])]['igp'])

>>>>>>> de7ab5c (Configuration automatique de OSPF et RIP + attribution d'addresse de loopback)
    except FileNotFoundError:
        print(f"Erreur : Fichier non trouvé.")
    except Exception as e:
        print(f"Erreur lors de l'exécution du script: {e}")