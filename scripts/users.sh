#!/bin/bash

# Groups
groupadd admin
groupadd dev
groupadd intern

# Users
useradd -m -s /bin/bash Vincent_bare
useradd -m -s /bin/bash Jules_fedit
useradd -m -s /bin/bash Ignacio_botella

# Group assignments
usermod -aG admin_role Vincent_bare
usermod -aG dev_role Jules_fedit
usermod -aG intern_role Ignacio_botella