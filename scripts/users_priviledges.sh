#!/usr/bin/env bash

set -euo pipefail

# Create users with home directory and bash shell
useradd -m -s /bin/bash Vicent_bare
useradd -m -s /bin/bash Jules_fedit
useradd -m -s /bin/bash Ignacio_botella

# Set passwords (plaintext for lab)
echo "Vicent_bare:pass_admin" | chpasswd
echo "Jules_fedit:pass_dev" | chpasswd
echo "Ignacio_botella:pass_intern" | chpasswd

# Create groups
groupadd admin || true
groupadd dev || true
groupadd intern || true

# Add users to groups
usermod -aG admin Vicent_bare
usermod -aG dev Jules_fedit
usermod -aG intern Ignacio_botella

# Show created users
cat /etc/passwd | grep -E "Vicent_bare|Jules_fedit|Ignacio_botella" 

cat /etc/group  | grep -E "admin|dev|intern" 

# Role configurations:

touch /etc/sudoers.d/admin
touch /etc/sudoers.d/dev
touch /etc/sudoers.d/intern

echo "%administrators ALL=(ALL:ALL) ALL" >> /etc/sudoers.d/admin
echo "%developers ALL=(ALL) NOPASSWD: /bin/mount, /bin/systemctl restart ssh" >> /etc/sudoers.d/dev





