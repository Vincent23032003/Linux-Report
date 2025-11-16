#!/bin/bash

# Install and configure auditd for system auditing
sudo apt install -y auditd audispd-plugins
sudo systemctl enable auditd
sudo systemctl start auditd
sudo systemctl status auditd

# Add custom audit rules
sudo nano /etc/audit/rules.d/hardening.rules


# Monitor passwd file changes
-w /etc/passwd -p rwa -k passwd_changes

# Monitor shadow file changes
-w /etc/shadow -p rwa -k shadow_changes

# Monitor root directory
-w /root/ -p rwa -k root_dir_monitoring

# Monitor privileged binaries
-w /usr/bin/sudo -p x -k privileged_sudo
-w /usr/bin/passwd -p x -k privileged_passwd
-w /usr/bin/mount -p x -k privileged_mount

# Apply the new audit rules
sudo auditctl -R /etc/audit/rules.d/hardening.rules
sudo auditctl -l

# Test audit rules by accessing monitored files
sudo cat /etc/shadow

