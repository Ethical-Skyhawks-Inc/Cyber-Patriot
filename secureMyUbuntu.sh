#!/bin/bash
#	Program:	BASH Ubuntu Security Scipts
#	File:		secureMyUbuntu.sh
#	Author:		omegablue
#********************************************************************
BLUE="\e[94m"
RED="\e[91m"
YELLOW="\e[93m"
GREEN="\e[92m"
NC="\e[0m"
printf "$GREEN<*> Ubuntu Security Scripts Started\n"

# Check for root access
printf "$GREEN<*> Checking for ROOT access...$NC\n"
if [[ $EUID -ne 0 ]]
then
	printf "$RED ROOT ACCESS NOT GRANTED, exiting...$NC\n"
	exit 1
fi

# Updates/Upgrades
printf "$BLUE<*> Update system files <Y|N>:$NC "
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	printf "$GREEN<*> Updating...$NC\n"	
	sudo apt-get -y update
fi
printf "$BLUE<*> Upgrade system software <Y|N>:$NC "
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	printf "$GREEN<*> Upgrading...$NC\n"
	sudo apt-get -y upgrade
fi

# Lock Out Root User
printf "$BLUE<*> Lock$RED ROOT$BLUE account <Y|N>:$NC "
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	printf "$GREEN<*> Locking$RED ROOT$GREEN...$NC\n"
	sudo passwd -l root
fi

# Disable Guest Account
printf "$GREEN<*> Disabling$RED GUEST$GREEN account...$NC\n"
printf "$YELLOW<*> Installing lightdm...$NC\n"
sudo apt-get -y install lightdm
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf

# Password & Login Policies
printf "$GREEN<*> Updating Password Policies...$NC\n"
printf "$YELLOW<*> Adding login authentication...$NC\n"
sudo sed -i "1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/" /etc/pam.d/common-auth
printf "$YELLOW<*> Adding password max age...$NC\n"
sudo sed -i "/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS  45" /etc/login.defs
printf "$YELLOW<*> Adding password minimum age...$NC\n"
sudo sed -i "/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10"  /etc/login.defs
printf "$YELLOW<*> Adding password expire warning...$NC\n"
sudo sed -i "/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7" /etc/login.defs
printf "$YELLOW<*> Installing cracklib...$NC\n"
sudo apt-get -y install libpam-cracklib
printf "$YELLOW<*> Adding password complexity...$NC\n"
sudo sed -i "1 s/^/password requisite pam_cracklib.so retry=3 minlen=10 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/" /etc/pam.d/common-password

# Remove Malware
malware=(hydra john medusa netcat nmap ophcrack)	# Add additional programs here
printf "$BLUE	Malware List\n"
printf "    --------------------$NC\n"
for prog in ${malware[@]} 
do
	printf "$YELLOW	$prog $NC\n"
done
printf "$BLUE<*> Purge malware from system <Y|N>:$NC "
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	for prog in ${malware[@]}
	do
		sudo apt-get -y purge $prog*
	done
fi

# Manage Media Files
endings=(aac wav mp3 mp4 wma mov avi gif jpg png bmp pdf txt img iso exe msi bat)	# Add additional suffix here
printf "$BLUE	Suffix List\n"
printf "    -------------------$NC\n"
for suffix in ${endings[@]} 
do
	printf "$YELLOW	$suffix $NC\n"
done
printf "$BLUE<*> Locate media files <Y|N>:$NC "
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	for suffix in ${endings[@]}
	do
		sudo find /home -name *.$suffix
	done
fi

# Install Software/Services
# Firewall
printf "$BLUE<*> Activate(Install) Firewall <Y|N>:$NC "
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	printf "$YELLOW<*> Installing Firewall...$NC\n"
	sudo apt-get -y install ufw
	printf "$YELLOW<*> Enabling Firewall...$NC\n"
	sudo ufw enable
fi

# MySQL
printf "$BLUE<*> Install/Uninstall MySQL <I|U|N>:$NC "
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Ii]$ ]]
then
	printf "$YELLOW<*> Installing MySQL...$NC\n"
	sudo apt-get -y install mysql-server
	printf "$YELLOW<*> Disabling remote access...$NC\n"
	sudo sed -i "/bind-address/ c\bind-address = 127.0.0.1" /etc/mysql/my.cnf
	printf "$YELLOW<*> Restarting MySQL...$NC\n"
	sudo service mysql restart
elif [[ $REPLY =~ ^[Uu]$ ]]
then
	sudo apt-get -y purge mysql*
fi

# OpenSSH
printf "$BLUE<*> Install/Uninstall OpenSSH <I|U|N>:$NC "
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Ii]$ ]]
then
	printf "$YELLOW<*> Installing OpenSSH...$NC\n"
	sudo apt-get -y install openssh-server
	printf "$YELLOW<*> Disabling$RED ROOT$YELLOW login...$NC\n"
	sudo sed -i "/^PermitRootLogin/ c\PermitRootLogin no" /etc/ssh/sshd_config
	printf "$YELLOW<*> Restarting Server...$NC\n"
	sudo service ssh restart
elif [[ $REPLY =~ ^[Uu]$ ]]
then
	sudo apt-get -y purge openssh-server*
fi

# VSFTPD
printf "$BLUE<*> Install/Uninstall VSFTPD <I|U|N>:$NC "
read -p "" -n 1 -r
echo
if [[ $REPLY =~ ^[Ii]$ ]]
then
	printf "$YELLOW<*> Installing VSFTPD...$NC\n"
	sudo apt-get -y install vsftpd
	printf "$YELLOW<*> Disabling$RED ANONYMOUS$YELLOW uploads...$NC\n"
	sudo sed -i '/^anon_upload_enable/ c\anon_upload_enable no' /etc/vsftpd.conf
	sudo sed -i '/^anonymous_enable/ c\anonymous_enable=NO' /etc/vsftpd.conf
	printf "$YELLOW<*> Configuring FTP directories...$NC\n"	
	sudo sed -i '/^chroot_local_user/ c\chroot_local_user=YES' /etc/vsftpd.conf
	printf "$YELLOW<*> Restarting VSFTPD...$NC\n"
	sudo service vsftpd restart
elif [[ $REPLY =~ ^[Uu]$ ]]
then
	sudo apt-get -y purge vsftpd*
fi

