# Projet NAS
Projet TC 2025 visant à automatiser la configuration de routeurs sur GNS3 (via Telnet) depuis des fichiers d'intention.

### Fonctionalité
____
- Configuration IP autonome à partir de plages d'addresses par AS
    - Support de plusieurs voisin sur une même interface (sur le même sous-réseau)  
    - Support de double (ou plus) connexions entre 2 même routeurs
- Mise place automatique des IGPs dans chaque AS
    - OSPF (support MPLS/LDP) 
- BGP 
    - iBGP
        - fullmesh sur les adresses de loopback
    - eBGP
        - connexions doubles entre 2 même routeurs
-BGP MPLS VPN
    - Service VPN entre différentes entitées dont les relations sont définit par un fichier d'intention

Auteurs : Gwendal Vantourout, Enzo Riviere, Benjamin Witters, Michel Melhem, Louis Alaux
