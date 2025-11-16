#!/usr/bin/env bash

set -euo pipefail

apt install acl -y

mkdir /opt/projects

chown root:admin /opt/projects
chmod 770 /opt/projects

setfacl -m "g:admin:rwx" /opt/projects
setfacl -m "g:dev:rw-" /opt/projects
setfacl -m "g:intern:r--" /opt/projects

getfacl /opt/projects

#umask reconfiguration

touch /etc/profile.d/custom_umask.sh
echo "umask 027" >> /etc/profile.d/custom_umask.sh

cat /etc/profile.d/custom_umask.sh

