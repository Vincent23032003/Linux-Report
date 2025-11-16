#!/bin/bash

# Create directory
mkdir -p /opt/projects

# Full rights for admin group
setfacl -m g:admin:rwx /opt/projects

# Dev: read + write
setfacl -m g:dev:rw /opt/projects

# Intern: read-only
# Needs +x on directory to traverse (required to read files)
setfacl -m g:intern:r-- /opt/projects
setfacl -m g:intern:rx /opt/projects

# Inheritance for newly created files
setfacl -d -m g:admin:rwx /opt/projects
setfacl -d -m g:dev:rw  /opt/projects
setfacl -d -m g:intern:r  /opt/projects