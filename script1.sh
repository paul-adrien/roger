Partie obligatoire
#1 : Mettre a jour les paquets
sudo apt-get update

sudo apt-get upgrade

sudo apt-get install sudo

#2 : Creation d'un user & se connecter
sudo adduser [user]

su - [user]

ajout de l'utilisateur dans le fichier sudoers qui lui permettra d'utiliser la commande sudo

usermod -aG sudo [user]

#3 : Configuration Interfaces Reseaux
editer le fichier /etc/network/interfaces

modifier la derniere ligne de iface eth0 inet dhcp a iface eth0 inet static

modifier la partie #Primary network interfaces pour :

auto enp0s3
iface enp0s3 inet static
->	address 192.168.1.1
->	netmask 255.255.255.252
puis effectuer la commande ip a afin de lister les interfaces reseaux, noter le nom de la 2e interface pour ajouter

auto [2e interface]
iface [2e interface] inet dhcp
la 2e interface sert a donner lacces internet a la VM

Puis redemarrer la VM

#4 Changer le port SSH
editer le fichier /etc/ssh/sshd_config

modifier la ligne #Port 22 pour mettre le port voulu (sans le #)

modifier la ligne #PermitRootLogin [...] vers PermitRootLogin no

modifier la ligne #PasswordAuthentication [...] vers PasswordAuthentication no

redemarrer le service ssh avec la commande suivante sudo /etc/init.d/ssh restart

generer une publick keys depuis l'hote de la VM a l'aide de la commande ssh-keygen

copier le contenu du fichier ~/.ssh/id_rsa.pub depuis la machine hote vers la VM
dans le fichier ~/.ssh/authorized_keys depuis la session a laquelle on souhaite
se connecter

#5 Firewall
Copier les commandes suivantes dans un fichier, executer ensuite le script cree en root

# #Nettoyage des règles existantes
# iptables -t filter -F
# iptables -t filter -X

# # Blocage total
# sudo iptables -t filter -P INPUT DROP
# sudo iptables -t filter -P FORWARD DROP
# sudo iptables -t filter -P OUTPUT DROP

# Garder les connexions etablies
# sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# sudo iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Autoriser loopback
sudo iptables -t filter -A INPUT -i lo -j ACCEPT
sudo iptables -t filter -A OUTPUT -i lo -j ACCEPT

# Refuser les requetes ICMP (ping)
sudo iptables -t filter -A INPUT -p icmp -j DROP
sudo iptables -t filter -A OUTPUT -p icmp -j DROP

# Autoriser SSH
# sudo iptables -t filter -A INPUT -p tcp --dport [port ssh] -j ACCEPT
# sudo iptables -t filter -A OUTPUT -p tcp --dport [port ssh] -j ACCEPT

# # Autoriser HTTP
# sudo iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
# sudo iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT

# # Autoriser HTTPS
# sudo iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT
# sudo iptables -t filter -A INPUT -p tcp --dport 8443 -j ACCEPT
# sudo iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT

# # Autoriser DNS
# sudo iptables -t filter -A INPUT -p tcp --dport 53 -j ACCEPT
# sudo iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT
# sudo iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
# sudo iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT
Les deux premieres lignes vont supprimer toutes les regles et tables deja existantes

Le deuxieme point va bloquer par defaut toutes les connexions

Le troisieme point va garder les connexions deja etablies

Le quatrieme point va autoriser les loopback (systeme qui renvoie un signal recu vers son envoyeur sans traitement)

Le cinquieme point va interdire le ICMP (Internet Control Message Protocol), le Ping

Le sixieme point va autoriser la connexion SSH sur le port SSH definit dans un point precedent

Les septieme et huitieme points autorisent la connexion sur les ports HTTP (80) et HTTPS (443)

# Le dernier point va autoriser les connexions au DNS, aussi bien sur le protocole TCP qu'UDP

#6 Protection DOS
Copier les commandes suivantes dans un fichier, executer ensuite le script cree en root

# Bloque les paquets invalides
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

# Bloque les nouveaux paquets qui n'ont pas le flag tcp syn
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# Bloque les valeurs MSS anormal
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

# Limite les nouvelles connexions
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

# Limite les nouvelles connexions si un client possede deja 80 connexions
iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset

# Limite les connections
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Protection Synflood
iptables -A INPUT -p tcp --syn -m limit --limit 2/s --limit-burst 30 -j ACCEPT

# Protection Pingflood
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
Le premier point bloque les paquets invalides sur tous les ports

Le deuxieme point bloque les paquets non synchronises (nouveaux paquets, non present sur la connexion deja etablie)

Le troisieme point bloque les valeurs MSS (Maximum Segment Size), c'est la quantite d'octets qu'un appareil peut contenir dans un seul paquet non fragmente. Au dela de cette MSS on sait que c'est un paquet errone

Le quatrieme point limite le nombre de nouvelle connexions qu’un client peut établir par seconde

Le cinquieme point limite le nombre de connexions a 25 par minute

Le sixieme point effectue une protection contre les attaques de type Synflood

Le septieme point effectue une protection contre les attaques de type Pingflood

#7 Protection de scans de ports
Copier les commandes suivantes dans un fichier, executer ensuite le script cree en root

# Protection scan de ports
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -m limit --limit 1/h -j ACCEPT
Ces deux lignes protegent le scan de ports

Afin de sauvegarder toutes ces regles et de les executer au demarrage de la machine, on doitu tiliser un package externe.

Linstaller avec la commande sudo apt-get install iptables-persistent

Et cliquer sur Yes lorsque le packet demande d'enregistrer les regles dans l'iptable

#8 Arreter les services
Installation graphique avec aucun services superflus installes, rien a arreter

#9 Script de mise a jour des packages
Editer le script :

sudo nano /root/scripts/script_log.sh

Et y mettre les lignes suivantes :

#!/bin/bash
apt-get update >> /var/log/update_script.log
apt-get upgrade >> /var/log/update_script.log
Ne pas oublier de lui attribuer les droits dexecution :

sudo chmod 755 /root/scripts/script_log.sh

Ainsi que de lui donner lutilisateur root afin qu'il n'y ai pas besoin dutiliser sudo :

sudo chown root /root/scripts/script_log.sh

Afin dautomatiser son execution, on modifie le fichier crontab en root avec la commande crontab -e

Pour y mettre les lignes suivantes :

0 4 * * wed root /root/scripts/script_log.sh
@reboot root /root/scripts/script_log.sh
#10 Script de surveillance du fichier crontab
Editer le script :

sudo nano /root/scripts/script_crontab.sh

Et y mettre les lignes suivantes :

#!/bin/sh

CRON_FILE=/etc/crontab
CHECK_FILE=/root/.crontab-checker

if [ ! -f $CHECK_FILE ] || [ "`md5sum < $CRON_FILE`" != "`cat $CHECK_FILE`" ]
then
    echo "The crontab file has been modified !" | mail -s "root: crontab modified" root
    md5sum < $CRON_FILE > $CHECK_FILE;
    chmod 700 $CHECK_FILE;
fi
Ne pas oublier de lui attribuer les droits d'execution :

sudo chmod 755 /root/scripts/script_crontab.sh

Ainsi que de lui donner l'utilisateur root afin qu'il n'y ai pas besoin d'utiliser sudo :

sudo chown root /root/scripts/script_crontab.sh

Afin d'automatiser son execution, on modifie le fichier crontab en root avec la commande crontab -e

Pour y mettre les lignes suivantes :

0 0 * * * root /root/scripts/script_crontab.sh