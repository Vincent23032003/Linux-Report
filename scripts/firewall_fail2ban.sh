#!/usr/bin/env bash

apt install ufw -y
apt install fail2ban -y


ufw allow 22/tcp
ufw allow http
ufw allow https
ufw allow 2222/tcp




ufw default deny incoming

ufw default deny outgoing

#Activate ufw to be persistant

ufw enable

#Activate logging

ufw logging on

ufw status verbose

#Fail2ban



touch /etc/fail2ban/jail.d/sshd.local


echo "[sshd]" >> /etc/fail2ban/jail.d/sshd.local
echo "enabled = true" >> /etc/fail2ban/jail.d/sshd.local
echo "port = 2222" >> /etc/fail2ban/jail.d/sshd.local
echo "maxretry = 3" >> /etc/fail2ban/jail.d/sshd.local
echo "bantime = 10m" >> /etc/fail2ban/jail.d/sshd.local
echo "logpath = /var/log/fail2ban.log" >> /etc/fail2ban/jail.d/sshd.local



systemctl enable fail2ban

systemctl start fail2ban

sleep 120

systemctl status fail2ban

fail2ban-client status sshd