# Projet GNS
Projet TC 2025 visant à automatiser la configuration de routeurs sur GNS3 (via Telnet) depuis des fichiers d'intention.

### Fonctionalité
____
- Configuration IP autonome à partir de plages d'addresses par AS
    - Support de plusieurs voisin sur une même interface (sur le même sous-réseau)  
    - Support de double (ou plus) connexions entre 2 même routeurs
- Mise place automatique des IGPs dans chaque AS
    - OSPF
    - RIP
- BGP 
    - iBGP
        - fullmesh sur les adresses de loopback
    - eBGP
        - Policies
            - pas de freelunch (route-map out)
            - attribution de communauté et de local-pref (route-map in)
        - connexions doubles entre 2 même routeurs

Auteurs : Gwendal VANTOUROUT, Enzo RIVIERE