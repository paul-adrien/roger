--------------
| Debian ISO |
--------------

https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-9.8.0-amd64-netinst.iso

--------------
| VirtualBox |
--------------

Create VM :
- Name : debian
- Type : Linux
- Version : Debian (64-bit)

Create a virtual hard disk :
- VDI, Dynamically allocated, 8.00 GB
- Path : /sgoinfre/goinfre/Perso/$USER/debian.vdi

Settings -> Network -> Attached to: Bridged Adapter.

Start VM.

----------------
| Installation |
----------------

Use Debian ISO and select Graphical Install
Default settings unless stated otherwise for the whole installation
Choose a root password
Create a non-root user
Partition :
	- Manual
	- 4.2 GB on Mount point `/` (shows as 4.2G with `sudo fdisk -l --bytes`)
	- 1.0 GB as swap area
	- 3.4 GB on Mount point `/home`
Finish partitioning
Software selection :
	- SSH server
	- standard system utilities

---------
| Setup |
---------

::::::::::
:: Sudo ::
::::::::::

Log in as the non-root user
`su` to log in as root
`apt-get install sudo vim -y`
`vi /etc/sudoers`
Add to the file :
```````````````````````````````````````````````````````````````````````````````
username	ALL(ALL:ALL) ALL
```````````````````````````````````````````````````````````````````````````````

You can now exit to go back to your non-root user and use sudo when you need root privileges

:::::::::::::::
:: Static IP ::
:::::::::::::::

`sudo vi /etc/network/interfaces`
Remove or comment the already existing enp0s3 interface
Cluster 3 example :
```````````````````````````````````````````````````````````````````````````````
auto enp0s3
allow-hotplug enp0s3
iface enp0s3 inet static
	address 10.13.42.21
	netmask 255.255.255.252
	gateway 10.13.254.254
	broadcast 10.13.255.255
	dns-nameservers 10.51.1.42
	
	# adress : In the same network as host, and not already taken
	# netmask : /30
	# gateway : `netstat -nr | grep default` (on MAC)
	# broadcast : `ifconfig en0 | grep broadcast` (on MAC)
	# dns-nameservers : `nslookup 42.fr`
```````````````````````````````````````````````````````````````````````````````
10.1X.0.0 is the network needed where X is the cluster
dns-nameservers is the same for cluster 1, 2 and 3
`sudo reboot`

:::::::::	
:: SSH ::
:::::::::

Server side :
- `sudo vi /etc/ssh/sshd_config`
- Uncomment 'Port 22' and replace it by 'Port 2222'
- Uncomment 'PermitRootLogin' and replace 'prohibit-password' by 'no'
- Uncomment 'PubkeyAuthentication yes'
- `sudo service sshd restart`

Client side :
- `ssh-copy-id -i ~/.ssh/id_rsa.pub username@hostIP -p 2222`
- `ssh username@hostIP -p 2222`

::::::::::::::
:: Firewall ::
::::::::::::::

`apt-get install ufw -y`
`sudo ufw allow 2222` #open ssh port
`sudo ufw enable` #activate firewall
`sudo ufw status` #check status
`sudo ufw allow XXXX` #open XXXX port

:::::::::
:: DOS ::
:::::::::

`apt-get install fail2ban -y`

/etc/fail2ban/jail.local
```````````````````````````````````````````````````````````````````````````````
[sshd]

enabled		= true
port		= 2222
logpath		= %(sshd_log)s
backend		= %(sshd_backend)s
maxretry	= 3
bantime		= 10
```````````````````````````````````````````````````````````````````````````````

`sudo service fail2ban restart`
`sudo fail2ban-client status`

:::::::::::::::::::::
:: Scan protection ::
:::::::::::::::::::::

`apt-get install portsentry -y`

/etc/portsentry/portsentry.conf
```````````````````````````````````````````````````````````````````````````````
BLOCK_UDP="1"
BLOCK_TCP="1"
```````````````````````````````````````````````````````````````````````````````

/etc/default/portsentry
```````````````````````````````````````````````````````````````````````````````
TCP_MODE="atcp"
UDP_MODE="audp"
```````````````````````````````````````````````````````````````````````````````

`sudo /etc/init.d/portsentry start`

Test scanning from another machine :
- `nmap -v TARGET_IP`
- `nmap -v -Pn -p 0-2000,60000 TARGET_IP`

Check if said machine was blocked :
- `cat /etc/hosts.deny`

Unblock machine :
- Remove line in /etc/hosts.deny

::::::::::::::
:: Services ::
::::::::::::::

`systemctl list-unit-files | grep enabled`
`sudo systemctl disable XXXXXXX`

Mandatory :
autovt@.service #Necessary for using virtual terminals
cron.service #Scheduled tasks
fail2ban.service #Protection against DOS
getty@.service #Necessary for login
networking.service #Network
ssh.service #Needed for SSH connection
sshd.service #Needed for SSH connection

:::::::::::::::::::
:: Update Script ::
:::::::::::::::::::

/etc/crontab
```````````````````````````````````````````````````````````````````````````````
0 4	* * 1	root    /etc/init.d/update_script.sh >> /var/log/update_script.log
@reboot		root    /etc/init.d/update_script.sh >> /var/log/update_script.log
```````````````````````````````````````````````````````````````````````````````

update_script.sh :
```````````````````````````````````````````````````````````````````````````````
#! /bin/bash
apt-get update && apt-get upgrade
```````````````````````````````````````````````````````````````````````````````

:::::::::::::::::
:: Cron Script ::
:::::::::::::::::

observer_cron.sh
```````````````````````````````````````````````````````````````````````````````
#!/bin/bash

# Last time /etc/crontab was modified (in seconds)
last_modif=`ls -l /etc/crontab --time-style=+%s | cut -d' ' -f6`

# Current time (in seconds)
now=`date +%s`

# Dfference between the two (in seconds)
diff=`expr $now - $last_modif`

# Dfference between the two (in hours)
diff=`expr $diff / 3600`

# Dfference between the two (in days)
diff=`expr $diff / 24`

# Is the difference in days lower than 1 ?
# or
# Has the file been modified in the last 24 hours ?
if [ $diff -lt 1 ]; then
	`sudo sendmail root@debian < /etc/init.d/observer_cron_mail.txt`
fi
```````````````````````````````````````````````````````````````````````````````

Write your own mail content in observer_cron_mail.txt

/etc/crontab
```````````````````````````````````````````````````````````````````````````````
0 0	* * *	root	/etc/init.d/observer_cron.sh
```````````````````````````````````````````````````````````````````````````````



iptables

# Reset rules
iptables		-F
iptables		-X
iptables -t nat		-F
iptables -t nat		-X
iptables -t mangle	-F
iptables -t mangle	-X

# Drop everything as default behavior
iptables -P INPUT	DROP
iptables -P OUTPUT	DROP
iptables -P FORWARD 	DROP

# Loopback
iptables -A INPUT	-i lo						-j ACCEPT
iptables -A OUTPUT	-o lo						-j ACCEPT

# DNS
iptables -A OUTPUT	-p tcp		--dport	53			-j ACCEPT
iptables -A OUTPUT	-p udp		--dport	53			-j ACCEPT

# SSH
iptables -A INPUT	-p tcp		--dport	2222			-j ACCEPT

# HTTP
iptables -A OUTPUT 	-p tcp		--dport	80			-j ACCEPT

# HTTPS
iptables -A OUTPUT	-p tcp		--dport	443			-j ACCEPT

# Outgoing ping
iptables -A OUTPUT	-p icmp		--icmp-type echo-request	-j ACCEPT
iptables -A INPUT	-p icmp		--icmp-type echo-reply		-j ACCEPT

# Already established connections
iptables -A INPUT	-m conntrack	--ctstate ESTABLISHED,RELATED	-j ACCEPT
iptables -A OUTPUT	-m conntrack	--ctstate ESTABLISHED,RELATED	-j ACCEPT