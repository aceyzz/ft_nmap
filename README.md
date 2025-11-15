<img title="42_ft_nmap" alt="42_ft_nmap" src="./utils/banner.png" width="100%">

<br>

# `ft_nmap` — 42

Ce projet a pour but de réaliser une version simplifiée de l'outil de scan réseau `nmap` en C, capable de scanner les ports TCP et UDP pour détecter leur état (ouvert, fermé, filtré).

<br>

## Description

Scanner réseau écrit en C utilisant des sockets brutes (raw sockets) pour envoyer des paquets TCP et UDP personnalisés à des adresses IP cibles, et `libpcap` pour capturer les réponses réseau. Le programme implémente six types de scan réseau distincts (SYN, NULL, FIN, XMAS, ACK, UDP) et permet le parallélisation des scans via des threads pour accélérer l'analyse.

<br>

## Architecture

Le projet repose sur plusieurs composants principaux :

**Parser** : Valide et traite les arguments en ligne de commande (adresses IP, plages de ports, types de scan, paramètres de parallélisation). Supporte trois modes d'entrée : IP unique avec `--ip`, fichier contenant des IPs avec `--file`, ou plage/liste de ports avec `--ports`. La détection automatique des paramètres par défaut (tous les ports 1-1024, tous les types de scan) offre une flexibilité maximale.

**Execution** : Crée les paquets TCP/UDP bruts avec les flags appropriés pour chaque type de scan et les envoie vers les ports cibles. Utilise des raw sockets (`SOCK_RAW`) avec un buffer de 1 Mo pour éviter la saturation réseau lors de scans massifs. Chaque paquet est envoyé avec un délai de 1ms pour permettre une meilleure gestion réseau.

**Thread Management** : Distribue intelligemment les types de scan et les ports parmi les threads parallèles (jusqu'à 250) pour une exécution optimale. Chaque thread gère un ensemble distinct de ports et de types de scan, synchronisé via mutex pour garantir l'intégrité des résultats stockés dans une structure d'état global.

**Packet Reception** : Utilise `libpcap` avec filtrage BPF compilé pour capturer uniquement les réponses des IPs cibles. Analyse les paquets TCP, UDP et ICMP reçus pour déterminer l'état de chaque port. Les réponses ICMP "Unreachable" indiquent un port fermé ou filtré, tandis que les réponses TCP avec flags SYN/ACK ou RST révèlent l'état exact du port.

**Checksum Calculation** : Implémente le calcul de checksum IPv4 standard pour les en-têtes TCP et UDP avec en-tête pseudo-IP, garantissant que les paquets sont acceptés par le système d'exploitation et les machines cibles.

**Result Display** : Présente les résultats organisés par adresse IP avec séparation entre ports ouverts et fermés/filtrés. Affiche les résultats de chaque type de scan pour chaque port, avec résolution des noms de services standards.

<br>

## Caractéristiques techniques

Le programme exige les droits root car les raw sockets nécessitent des privilèges elevés. Les détails clés incluent :

- **Sockets brutes** : Configuration avec `SO_SNDBUFFORCE` (1 Mo) pour éviter les erreurs de saturation de buffer réseau
- **Parallélisation** : Distribution optimale des threads basée sur le nombre de scans et ports (jusqu'à 250 threads)
- **Timeout global** : Signal `SIGALRM` fixé à 15 secondes, réinitialisé après chaque paquet reçu (5 secondes de relâchement)
- **Synchronisation** : Mutex protégeant le tableau d'état global pour garantir la sécurité en présence de threads multiples
- **Filtrage réseau** : Filtre BPF compilé pour capturer uniquement les réponses des IPs cibles
- **Types de scan** : 
  - **SYN** : Scan TCP standard (connexion à trois voies)
  - **NULL** : Aucun flag TCP activé
  - **FIN** : Seulement le flag FIN activé
  - **XMAS** : Flags FIN, PSH et URG activés
  - **ACK** : Seulement le flag ACK activé
  - **UDP** : Scan UDP basé sur les réponses ICMP

<br>

## Utilisation

### Compilation

Lancer l'environnement sandbox avec Docker contenant les cibles de test
```bash
git clone https://github.com/aceyzz/ft_nmap.git
cd ft_nmap/project
docker compose up -d --build
docker exec -it ft_nmap bash
```

Une fois dans le docker, compiler le projet
```bash
# droits roots necessaires pour les raw sockets
sudo su
make			  # Compile le scanner
# autres commandes make disponibles :
make clean		  # Supprime les fichiers objets
make fclean		  # Supprime les fichiers objets et l'exécutable
make re			  # Recompile à partir de zéro
make leaks		  # Exécute le scanner avec valgrind pour détecter les fuites mémoire
```

### Lancement

Le scanner doit être exécuté en tant que root car il nécessite l'accès aux raw sockets.

```bash
sudo su
./ft_nmap --help				  # Affiche l'aide
./ft_nmap --ip 10.0.0.10 --ports 80,443,8080 --scan SYN  # Scan spécifique
./ft_nmap --ip target_nc --ports 1-1024 --speedup 50   # Scan parallélisé
./ft_nmap --file targets.txt  # Scan depuis un fichier
```

### Options disponibles

```plaintext
--help              Affiche cette aide
--ports             Ports à scanner (ex: 1-10 ou 1,2,3 ou 1,5-15)
--ip                Adresse(s) IP à scanner au format dot (ex: 192.168.1.1)
--file              Fichier contenant les adresses IP à scanner
--speedup [max 250] Nombre de threads parallèles à utiliser
--scan              Types de scan (SYN, NULL, FIN, XMAS, ACK, UDP)
```

### Exemple d'exécution

```bash
# Scanner les ports 22, 80, 443 sur l'IP 10.0.0.10 avec un scan SYN
./ft_nmap --ip 10.0.0.10 --ports 22,80,443 --scan SYN

# Scanner la plage 1-1024 sur plusieurs IPs avec parallélisation
./ft_nmap --file targets.txt --ports 1-1024 --speedup 100

# Scanner tous les types de scan sur une plage de ports sans parallélisation
./ft_nmap --ip 10.0.0.20 --ports 80-85 --scan SYN,ACK,FIN
```

<br>

## Choix d'implémentation

**Sockets brutes (Raw Sockets)** : Utilisation de `SOCK_RAW` avec `IPPROTO_TCP` et `IPPROTO_UDP` pour construire entièrement les paquets TCP/UDP au niveau applicatif. Permet un contrôle total des flags et du contenu, essentiel pour les types de scan spécialisés.

**Buffer réseau dimensionné** : Configuration de `SO_SNDBUFFORCE` à 1 Mo (1024 * 1024 bytes) pour éviter les erreurs "no buffer space available" lors de scans massifs sur de nombreux ports simultanément.

**Parallélisation intelligente** : Distribution des threads par type de scan d'abord, puis par port. Fonction `ft_setter()` qui distribue équitablement les ports parmi les threads assignés à chaque type de scan pour maximiser l'efficacité.

**Capture avec libpcap** : Utilisation de filtres BPF compilés pour ne capturer que les réponses des IPs cibles, réduisant significativement le bruit réseau et l'utilisation CPU. Le filtre est une disjonction de conditions "host X.X.X.X".

**Calcul de checksum** : Implémentation manuelle du checksum IPv4 avec en-tête pseudo-IP TCP/UDP. Essentiel pour que le système d'exploitation accepte les paquets générés par les raw sockets.

**Gestion des signaux** : Signal `SIGALRM` configuré avec un timeout initial de 15 secondes, réinitialisé à 5 secondes chaque fois qu'un paquet est reçu. Permet une écoute flexible : rapide si des réponses arrivent, mais avec une limite de temps globale.

**Synchronisation inter-thread** : Mutex `pthread_mutex_t` protégeant le tableau global `state[scan][port]` pour éviter les race conditions lors de l'écriture des états de port simultanément par plusieurs threads.

**Structure union pour les headers** : Union `t_packet_header` permettant d'accéder à `iphdr`, `tcphdr`, `udphdr` et `icmphdr` via le même pointeur, simplifiant le traitement polymorphe des paquets.

<br>

## Liens utiles

- [Sujet officiel](./utils/en.subject.pdf)

<br>

## Grade

> En cours d'évaluation

<br>

## Authors

<div style="display: flex; gap: 2rem; align-items: center;">

<div align="center">
<a href="https://github.com/cduffaut" target="_blank">
	<img src="https://img.icons8.com/?size=100&id=tZuAOUGm9AuS&format=png&color=000000" width="40" alt="GitHub Icon"/>
	<br>
	<b>Cécile</b>
</a>
</div>

<div align="center">
<a href="https://github.com/aceyzz" target="_blank">
	<img src="https://img.icons8.com/?size=100&id=tZuAOUGm9AuS&format=png&color=000000" width="40" alt="GitHub Icon"/>
	<br>
	<b>Cédric</b>
</a>
</div>

</div>
