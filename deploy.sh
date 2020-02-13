# 1. Installation de VM dans VirtualBox
# Vérifiez dans les préférences que le dossier par défaut de la machine
# est / sgoinfre / goinfre / Perso / epham / VM

# Paramètres VM:

# dans le stockage: assurez-vous que Controller: IDE a un disque debian-9.9.0
# dans le réseau: attaché à l' adaptateur ponté , nom: en0: ethernet
# Installation de VM

# Nom d'hôte:

roger
# Laissez le nom de domaine vide
# Suivez les étapes pour créer un nouvel utilisateur

# Exigences de partitionnement:

# Taille du disque de 8 Go.
# Au moins une partition de 4.2 Go.
# La machine virtuelle doit également être à jour avec tous les packages nécessaires au projet installé.
# Méthode de partitionnement:

Manual
# Sélectionnez une partition pour modifier ses paramètres:

# SCSI1 (0, 0, 0) (sda) 8.6 GB ATA VBOX HARDDISK
# Créez une nouvelle table de partition vide sur cet appareil: < Oui > Sélectionnez une partition pour modifier ses paramètres:

pri/log 8.6 GB FREE SPACE
# Sélectionnez Créer une nouvelle partition

# Nouvelle taille de partition:

4.5 GB
# Saisissez la nouvelle partition:

Primary
# Sélectionnez Terminé configuration de la partition

# Sélectionnez une partition pour modifier ses paramètres:

pri/log 4.1 GB FREE SPACE
# Sélectionnez Créer une nouvelle partition

# Nouvelle taille de partition:

4.1 GB
# Saisissez la nouvelle partition:

Logical
# Sélectionnez Terminer le partitionnement et écrire les modifications sur le disque

# Voulez-vous revenir au menu de partitionnement? < Non >
# Ecrire les modifications sur les disques? < Oui > Numériser un autre CD ou DVD? < Non >

# Pays miroir des archives Debian

France
ftp.fr.debian.org
# Laissez les informations du proxy HTTP vides

# Participer à l'enquête sur l'utilisation des packages? < Non >

# Logiciels à installer:

 ... Environnement de bureau Debian
 ... GNOME
 ... Xfce
 ... KDE
 ... Cannelle
 ... CAMARADE
 ... LXDE
 serveur Web
 ... serveur d'imprimante
 Serveur SSH
 Utilitaires système standard
# Installer le chargeur de démarrage GRUB sur l'enregistrement de démarrage principal? < Oui >

# Dispositif d'installation du chargeur de démarrage

/dev/sda (ata-VBOX_HARDDISK)


# Packages installés
apt install sudo
apt install net-tools (for ifconfig)
apt install vim
# Créer un utilisateur non root pour se connecter à la machine et travailler (ajouter un utilisateur aux sudoers)
usermod -aG sudo username
# Vérifiez si l'utilisateur peut effectuer des opérations sudo
sudo fdisk -l


# 2. Partie réseau et sécurité
# Nous ne voulons pas que vous utilisiez le service DHCP de votre machine.
# Vous devez le configurer pour avoir une IP statique et un masque de réseau dans \ 30.
# Obtenir l'adresse IP de la VM

sudo ifconfig
# Mon adresse IP: 10.12.1.106
# Utilisez un service statique au lieu de DHCP

sudo vim /etc/network/interfaces
# remplacer dhcppar static
# ajouter ces lignes:

address 		10.12.1.106   	# IP address of VM
gateway 		10.12.254.254 	# Gateway address of VM
broadcast 		10.12.255.255   # Broadcast address of VM
netmask                 255.255.255.252 # Netmask /30
11111111 11111111 11111111 11111100
# ensuite

sudo reboot
# Vous devez changer le port par défaut du service SSH par celui de votre choix.
#L'accès SSH DOIT être fait avec des publickeys.
#L'accès root SSH NE DEVRAIT PAS être autorisé directement,
#mais avec un utilisateur qui peut être root.
# Modifier le port SSH par défaut

sudo vim /etc/ssh/sshd_config
# uncomment ligne # Port 22et le changement 22comme 24(ou tout autre numéro de port disponible)
# ligne uncomment# PasswordAuthentication yes

sudo service sshd restart
# Connectez-vous sur votre machine via SSH à la VM
ssh plaurent@10.12.1.106 -p 2670
# Générer un publickey pour accéder à VM via SSH

# Sur votre machine (pas la VM)

ssh-keygen
# fichier dans lequel enregistrer la clé /home/plaurent/.ssh/id_rsa

# Copiez le publickey dans le fichier VM publickeys, puis à partir de la machine (pas VM)

cd .ssh/
ssh-copy-id -i id_rsa.pub plaurent@10.12.1.106 -p 2670
# Vérifiez sur VM qu'un nouveau fichier authorized_keys a été créé dans le dossier .ssh /

# Pour interdire à root de se connecter via SSH

sudo vim /etc/ssh/sshd_config
# décommenter la ligne # PermitRootLogin restrict-passwordet remplacer restrict-passwordparno

# Pour autoriser l'accès SSH via publickeys UNIQUEMENT

# décommenter la # PubkeyAuthentication yes
# ligne # PasswordAuthentication yesremplacer yesparno

# puis redémarrez le service ssh

sudo service sshd restart



# Vous devez définir les règles de votre pare-feu sur votre serveur uniquement avec les services 
#utilisés en dehors de la machine virtuelle.
# Pour ce faire, nous utiliserons iptables.

# Installer iptables-persistent pour rendre le changement de règle permanent

sudo apt-get install iptables-persistent
# Démarrez le service, il doit créer le dossier / etc / iptables / 
#contenant les fichiers de règles (ipv4 et ipv6)

sudo service netfilter-persistent start
# Ajout de règles au pare-feu

# Tout d'abord, obtenez l'adresse IP de la machine ( ifconfigen commençant par en ou ip a)

# autoriser tout le trafic pour le port ssh (parce que nous voulons pouvoir nous connecter via ssh)
sudo iptables -A INPUT -p tcp -i enp0s3 --dport 24 -j ACCEPT
# (pour autoriser toute connexion au port 24)

# Ensuite, enregistrez-le en tant que changement permanent

sudo service netfilter-persistent save
# Nous pouvons également ajouter des règles directement en les éditant dans les
#fichiers /etc/iptables/rules.v4ou /etc/iptables/rules.v6.
#J'ai ajouté les règles suivantes

# SSH CONNECTION
-A INPUT -i enp0s3 -p tcp -m tcp --dport 24 -j ACCEPT

# WEB PORTS
-A INPUT -i enp0s3 -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -i enp0s3 -p tcp -m tcp --dport 443 -j ACCEPT

# DNS PORTS (tcp and udp)
-A INPUT -i enp0s3 -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -i enp0s3 -p udp -m udp --dport 53 -j ACCEPT

# TIME PORT
-A INPUT -i enp0s3 -p udp -m udp --dport 123 -j ACCEPT
# Pour les enregistrer directement à partir de ces fichiers, nous pouvons utiliser la commande

sudo service netfilter-persistent reload


# Vous devez définir une protection DOS (Denial Of Service Attack) sur vos ports ouverts de votre machine virtuelle.
# https://www.supinfo.com/articles/single/2660-proteger-votre-vps-apache-avec-fail2ban

# Installation d'une protection contre les attaques DOS sur les ports ouverts

sudo apt install fail2ban
# Copiez le fichier de configuration dans un fichier local et configurez la protection

cd /etc/fail2ban
sudo cp jail.conf jail.local
sudo vim jail.local
# en SSH SERVERS SECTION
# tout remplacer port = sshparport = 24

# dans la section JAILSsous HTTP servers, ajouter ce qui suit

# Block login attempts
[apache]

enabled  = true
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache2/*error.log
maxretry = 3
bantime  = 600
ignoreip = 10.12.1.140

# DOS protection
[apache-dos]

enabled  = true
port     = http,https
filter   = apache-dos
logpath  = /var/log/apache2/access.log
bantime  = 600
maxretry = 300
findtime = 300
action   = iptables[name=HTTP, port=http, protocol=tcp]
ignoreip = 10.12.1.140

# ADD THE FOLLOWING LINES TO THE SECTIONS [apache-badbots] [apache-noscript] [apache-overflows]

enabled  = true
filter   = section-name
logpath  = /var/log/apache2/*error.log
ignoreip = 10.12.1.140
# Créer apache-dos.conf fichier dans filters.d dossier:

cd /etc/fail2ban/filters.d/
sudo touch apache-dos.conf
sudo vim apache-dos.conf
# Ajoutez ce qui suit:

# [Definition] 
# failregex = ^<HOST> -.*"(GET|POST).*
# ignoreregex =

# Activez ensuite [apache dos] dans le fichier defaults-debian.conf

sudo vim /etc/fail2ban/jail.d/defaults-debian.conf

# ADD THESE LINES
[apache]
enabled = true

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true

[apache-badbots]
enabled = true

[apache-dos]
enabled = true
# Et redémarrez le service

sudo service fail2ban restart
# Pour vérifier si la règle de pare-feu est appliquée

# Essayez de vous connecter via ssh à la machine avec un identifiant / mot de passe incorrect jusqu'à ce qu'il soit bloqué
# Remarque : ce n'est pas l'utilisateur qui est bloqué mais l'adresse IP de la machine à partir de laquelle le mauvais utilisateur a tenté de se connecter. Par conséquent, même un utilisateur valide ne pourra pas se connecter via ssh à la machine virtuelle à partir de cette adresse IP.

# Pour débloquer l'adresse IP, revenez à la machine virtuelle

sudo fail2ban-client status sshd
# pour vérifier que votre adresse IP est dans la section interdite

sudo fail2ban-client set sshd unbanip your_ip_address
# puis redémarrez le service fail2ban

sudo service fail2ban restart
# Protection DDOS sur les ports ouverts de votre machine virtuelle. (alias attaques multiples)
# Utilisation d'IPTABLES
# https://javapipe.com/blog/iptables-ddos-protection/

# Installation d'un service qui rendra les modifications de règles permanentes

sudo apt-get install iptables-persistent
# BLOCKING INVALID PACKETS
sudo iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

# BLOCKING NEW PACKETS THAT ARE NOT SYN
sudo iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# BLOCKING Packets With Bogus TCP Flags
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
sudo iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
  
# Block Packets From Private Subnets (Spoofing)
sudo iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
# NOT THIS ONE SINCE OUR IP ADDRESS IS 10.12.1.140
# sudo iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP 
sudo iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
# Enregistrer ces règles comme permanentes

sudo service netfilter-persistent save
sudo service netfilter-persistent restart
# puis redémarrez

sudo reboot
# Pour tester si cela fonctionne, utilisez slowloris

# Pour redonner accès à la machine qui a été bloquée

sudo iptables -L # see banned ip
sudo fail2ban-client set apache-dos unbanip 10.12.6.12

sudo service fail2ban restart



# Vous devez définir une protection contre les analyses sur les ports ouverts de votre machine virtuelle.
# Installation d'une protection contre l'analyse des ports

sudo apt install portsentry
# Configuration de portsentry
# https://wiki.debian-fr.xyz/Portsentry

cd /etc/portsentry
sudo vim portsentry.conf
# Décommentez les premières lignes TCP et UDP (la protection la plus élevée) Commentez les secondes
# lignes TCP et UDP (protection moyenne)

# remplacer
TCP_MODE="tcp"par TCP_MODE="atcp" UDP_MODE="udp"parUDP_MODE="audp"

# ensuite

sudo vim /etc/portsentry/portsentry.conf
# remplacer
BLOCK_UDP="0"par BLOCK_UDP="1" BLOCK_TCP="0"parBLOCK_TCP="1"

# Sous COMMANDES EXTERNES

KILL_RUN_CMD="/sbin/iptables -I INPUT -s $TARGET$ -j DROP && /sbin/iptables -I INPUT -s $TARGET$ -m limit --limit 3/minute --limit-burst 5 -j LOG --log-level debug --log-prefix 'Portsentry: dropping: '"
# Pour vous assurer que notre propre adresse IP n'est pas interdite:

sudo vim /etc/portsentry/portsentry.ignore.static
# Ajoutez vos adresses IP et inet

# puis redémarrez le service portsentry:

sudo service portsentry restart
# Pour vérifier si la protection Portscan est appliquée

# Depuis une machine, essayez

nmap -Pn 10.12.1.140
# Vous devriez être expulsé de la machine virtuelle si vous étiez connecté via ssh

# Pour supprimer votre adresse IP du fichier d'hôtes refusés

sudo vim /etc/hosts.deny
# Supprimer l'adresse IP de la machine à partir de laquelle vous avez effectué le nmap

# Ensuite, nous devons supprimer notre interdiction des iptables

sudo iptables -D INPUT 1
sudo iptables -D INPUT 1
# puis redémarrez

sudo reboot
# Arrêtez les services dont vous n'avez pas besoin pour ce projet.
# Pour ce faire, nous allons faire un clone lié de notre VM. Et désactivez les services sur la machine virtuelle clonée pour voir quels services sont nécessaires pour le projet.

# Déconnectez-vous, fermez et éteignez votre machine virtuelle
# Clic droit dans VirtualBox sur Clone ...
# Continuer et cocher le clone lié
# Ensuite, ouvrez la machine virtuelle clonée

# Vérifier les services en cours d'exécution

sudo systemctl list-units -t service
# ou

sudo systemctl list-unit-files --state=enabled
# ou

sudo service --status-all
# Voici tous les services en cours d'exécution:

UNIT FILE                    STATE
autovt@.service              enabled
console-setup.service        enabled
cron.service                 enabled
fail2ban.service             enabled
getty@.service               enabled
keyboard-setup.service       enabled
netfilter-persistent.service enabled
networking.service           enabled
rsyslog.service              enabled
ssh.service                  enabled
sshd.service                 enabled
syslog.service               enabled
systemd-timesyncd.service    enabled
remote-fs.target             enabled
apt-daily-upgrade.timer      enabled
apt-daily.timer              enabled
# Tous les services répertoriés ci-dessus sont utiles, car ce sont les services par défaut disponibles.

# Pour désactiver un service:

sudo systemctl disable service_name


# Créez un script qui met à jour toutes les sources de package, puis vos packages et qui
#enregistre le tout dans un fichier nommé /var/log/update_script.log. Créez une tâche planifiée pour ce script
#une fois par semaine à 4 heures du matin et à chaque redémarrage de la machine.
# Puisque nous avons besoin que la tâche cron vienne de la racine, nous nous connecterons en tant qu'utilisateur root

su
touch autoupdate.sh
sudo vim autoupdate.sh
# Ensuite, nous devons créer le fichier journal nommé * / var / log / update_script.log *

touch /var/log/update_script.log
# Maintenant, écrivez le script de mise à jour ET pour enregistrer le processus de mise à jour complet dans le fichier journal

#!/bin/bash

date >> /var/log/update_script.log                    # date of update
apt-get -y -q update >> /var/log/update_script.log
apt-get -y -q upgrade >> /var/log/update_script.log
echo "\n" >> /var/log/update_script.log               # \n between each update
# Ensuite, en tant que root

crontab -e
# A la fin du fichier, pour régler la mise à jour à 4h du matin chaque semaine:

# minute hour dayofmonth month dayofweek command
# Update every week at 4 am
0 4 * * 1 /bin/sh /root/autoupdate.sh

# Update at every reboot
@reboot /bin/sh /root/autoupdate.sh
# Créez un script pour surveiller les modifications du fichier / etc / crontab et envoyez un e-mail à root s'il a été modifié. Créez une tâche de script planifiée tous les jours à minuit.
apt-get install mailutils
touch cronchanges.sh
vim /etc/aliases
# Assurez-vous que tous les e-mails vont à la racine et ne sont pas redirigés:

mailer-daemon: postmaster
postmaster: root
nobody: root
hostmaster: root
usenet: root
news: root
webmaster: root
www: root
ftp: root
abuse: root
noc: root
security: root
root: root
# Écrivez le script

cd
sudo vim cronchanges.sh
#!/bin/sh

diff /etc/crontab /etc/current > /dev/null 2> /dev/null
if [ $? -ne 0  ]
then
	echo "The crontab file has been modified\n" | mail -s "Crontab" root@localhost
	cp /etc/crontab /etc/current
fi
# Redémarrez ensuite et reconnectez-vous en tant que root

reboot
# Pour ajouter le script à la crontab:

crontab -e

0 0 * * * /bin/sh /root/cronchanges.sh