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



def get_subnets(connections, routeur_data, as_data):
    subnets = {}
    as_subnets = {}

    for as_id, as_entry in as_data.items():
        subnets_brut = as_entry.get('plage_adresse', [])
        as_subnets[as_id] = []
        for subnet_brut in subnets_brut:
            network = ipaddress.IPv6Network(subnet_brut)
            as_subnets[as_id].extend(network.subnets(new_prefix=64))
        as_subnets[as_id] = iter(as_subnets[as_id])

    tous_les_subnets = set()

    for (routeur1, interface1), (routeur2, interface2) in connections:
        # Attribuer un sous-réseau uniquement si les deux interfaces n'en ont pas déjà un
        if (routeur1, interface1) not in subnets and (routeur2, interface2) not in subnets:
            as_id1 = str(routeur_data[routeur1]['AS_number'])
            as_id2 = str(routeur_data[routeur2]['AS_number'])
            as_id = as_id1 if as_id1 <= as_id2 else as_id2
            subnet = next(as_subnets[as_id])
            if subnet not in tous_les_subnets:
                subnets[(routeur1, interface1)] = str(subnet)
                subnets[(routeur2, interface2)] = str(subnet)
                tous_les_subnets.add(subnet)
            else:
                while True:
                    subnet = next(as_subnets[as_id])
                    if subnet not in tous_les_subnets:
                        subnets[(routeur1, interface1)] = str(subnet)
                        subnets[(routeur2, interface2)] = str(subnet)
                        tous_les_subnets.add(subnet)
                        break
    return subnets

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

def configure_routeur_telnet(routeur, config, subnets, as_data):
    """Configure les routeurs via Telnet avec Exscript."""
    try:
        host = "localhost"
        port = config['port_telnet']
        conn = Telnet()
        conn.connect(host, port)
        print(f"Connexion à {routeur} sur le port {port}...")



        conn.send("\rconfigure terminal\r")
        
        for (r, interface), subnet in subnets.items():
            if r == routeur and subnet != "Aucune plage disponible":
                ipv6_address = ipaddress.IPv6Network(subnet).network_address + 1
                conn.send(f"interface {interface}\r")
                conn.send(f"ipv6 address {ipv6_address}/{ipaddress.IPv6Network(subnet).prefixlen}\r")
                conn.send("no shutdown\r")
        conn.send("end\r")
        conn.send("write memory\r\r")
        conn.send("exit\r")
        print("OKk")
        #conn.close() Faudrait faire ça pour fermer proprement les connections telnet, mais dans ce cas là le programme plante ????

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

        subnets = get_subnets(connections, routeur_data, as_data)
        affiche_connexion(connections, subnets)
        affiche_erreur(erreurs)

        for routeur, config in routeur_data.items():
            configure_routeur_telnet(routeur, config, subnets, as_data)

    except FileNotFoundError:
        print(f"Erreur : Fichier non trouvé.")
    except Exception as e:
        print(f"Erreur lors de l'exécution du script: {e}")