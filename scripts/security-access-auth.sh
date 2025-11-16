#!/usr/bin/env bash

set -euo pipefail

#Install an enable ssh server

#apt install openssh-server

systemctl enable ssh


#Disable password login and enable only authentication via asymetric keys

echo "PasswordAuthentication no" >> /etc/ssh/ssh_config
echo "PubKeyAuthentication yes" >> /etc/ssh/ssh_config

#Use an alternative port, port 2222
echo "Port 2222" >> /etc/ssh/ssh_config

#Allow the users we created to use the ssh service
echo "AllowUsers Vicent_bare Jules_fedit Ignacio_botella" >> /etc/ssh/ssh_config

#Create an custom banner

touch /etc/ssh/ssh_config.d/custom_banner

echo "
    *********************************************
    *Authorized access only                     *
    *                                           *
    *If you are not Vincent, Jules or Ignacio.  *
    *Please disconnect INMEDIATLY               *
    *********************************************" >> /etc/ssh/ssh_config.d/custom_banner



echo "Banner /etc/ssh/ssh_config.d/custom_banner" >> /etc/ssh/ssh_config

#Create keys for the users and authorize them

ssh-keygen -t ed25519 -f ~/.ssh/vincent_id25519 -C "Vincent_bare@ece" -N ""
ssh-keygen -t ed25519 -f ~/.ssh/jules_id25519 -C "Jules_fedit@ece" -N ""
ssh-keygen -t ed25519 -f ~/.ssh/ignacio_id25519 -C "Ignacio_botella@ece" -N ""

#The part of copying the pub keys should be done with the command ssh-copy-id 
#But we are installing this in our localhost so it's no necessary but not the best practice



cat ~/.ssh/vincent_id25519.pub >> ~/.ssh/authorized_keys
cat ~/.ssh/jules_id25519.pub >> ~/.ssh/authorized_keys
cat ~/.ssh/ignacio_id25519.pub >> ~/.ssh/authorized_keys

chmod 600 ~/root/.ssh/authorized_keys
chmod 700 ~/root/.ssh

#Harden Cyphers and cryptographics algorithms 

echo "Ciphers aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/ssh_config
echo "MACs hmac-sha512,hmach-sha256" >> /etc/ssh/ssh_config
echo "KexAlgorithms curve25519-sha256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/ssh_config

#Resatart ssh service

systemctl restart ssh

#Check configuration
sshd -T | grep ciphers
sshd -T | grep macs
sshd -T | grep kexalgorithms
sshd -T | grep port
sshd -T | grep allowusers

sleep 60

ss -tlnp | grep sshd