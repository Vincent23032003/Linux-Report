# Linux Security Hardening – ECE Paris – ING5 CYB  
### **Team: Vincent Baré – Jules Fedit – Ignacio Botella**  
### **Group: Gr03 – TP03**


![Image 1](images/1.png)
---

# Table of Contents
- [1. Context](#1-context)
- [2. Environment & Requirements](#2-environment--requirements)
  - [2.1 VM & OS](#21-vm--os)
  - [2.2 Constraints](#22-constraints)
- [3. Team Methodology](#3-team-methodology)
- [4. References](#4-references)
- [5. Scripting Approach](#5-scripting-approach)
- [6. Technical Exercises](#6-technical-exercises)
  - [6.1 Users & Privileges](#61-users--privileges)
  - [6.2 Fine-Grained Access](#62-fine-grained-access)
  - [6.3 SSH Hardening & Authentication Security](#63-ssh-hardening--authentication-security)
  - [6.4 Firewall & Intrusion Protection](#64-firewall--intrusion-protection)
  - [6.5 Data Encryption & Protection](#65-data-encryption--protection)
  - [6.6 Audit System](#66-audit-system)
- [7. Conclusion](#7-conclusion)

---

# 1. Context

The goal of this hands-on project is to **secure a freshly installed Linux server (Ubuntu 24.04)** as a cybersecurity team.  
We applied hardening techniques aligned with **CIS Benchmark**, **ANSSI recommendations**, and security best practices.

Each part includes:
- Explanation & justification  
- Scripts  
- Proof (screenshots directory on GitHub)  

---

# 2. Environment & Requirements

## 2.1 VM & OS
Hostname required format: ECEPa_I5_Gr03_GRTP03


System verification command executed:
``````bash
sudo apt update; echo -e "\n\n\nHost: $(hostname)"; echo -e "Kernel: $(uname -r)\n"; echo "OS info:"; cat /etc/os-release; echo -e "\nDate: $(date)"; echo "apt: $(apt list -upgradable 2>/dev/null | grep -c upgradable)" 
``````

![hostnameConfig](images/hostnameConfig.png)


Screenshots available in:  
📁 `/screenshots/system/`

## 2.2 Constraints
We followed all mandatory constraints:
- hostname format respected  
- user naming format respected  
- no root login allowed  
- no password SSH authentication  
- scripts used wherever possible  

---

# 3. Team Methodology

| Task | Member |
|------|--------|
| Users, groups, sudoers | Vincent |
| ACL, umask configuration | Vincent |
| SSH Hardening | Jules |
| UFW + Fail2Ban configuration | Ignacio |
| LUKS + VeraCrypt | Jules |
| Auditd monitoring | Ignacio |
| Documentation (GitHub) | Shared |

We used GitHub to coordinate work and share scripts.  
All screenshots were taken individually and verified as a group.

---

# 4. References

We used the following security references:

- **CIS Benchmark Ubuntu 24.04 LTS**
- **ANSSI RGS v2.0 – SSH recommendations**
- Ubuntu Documentation:  
  https://ubuntu.com/server/docs
- manpages:  
  `man sshd_config`, `man pam_faillock`, `man ufw`, `man auditd`

These references guided our decisions regarding:
- umask (027 recommended by CIS)  
- SSH ciphers, KEX & MAC configuration  
- sudoers restrictions  
- firewall policies  

---

# 5. Scripting Approach

Automation was used wherever relevant.  
All scripts are located in:

`/scripts/`

Scripts available:
- `01_users.sh`  
- `02_acls_umask.sh`  
- `03_ssh_hardening.sh`  
- `04_ufw_fail2ban.sh`  
- `05_luks_setup.sh`  
- `06_auditd_rules.sh`  

Each script is **idempotent** and can be executed on any fresh Ubuntu VM.

---

# 6. Technical Exercises

---

# 6.1 Users & Privileges

## Objective
- Create admin, dev, intern accounts  
- Configure granular sudo access  
- Lock account after 3 failed sudo attempts (5 min lock)

---

## Users & Groups Creation

### Script: `/scripts/01_users.sh`
```bash
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
```




## Verification

### Users exist
![UsersCreation](images/usersCreation.png)


### Groups exist

![Group Creation](images/groupCreation.png)


### Each user assigned properly
![id](images/id.png)


## Sudoers Configuration

![sudoersRights](images/sudoersRigths.png)


## Account Lockout Policy (PAM)

We used the CIS-recommended faillock module.
File: /etc/pam.d/common-auth

```bash
auth required pam_faillock.so preauth silent deny=3 unlock_time=300
auth [default=die] pam_faillock.so authfail deny=3 unlock_time=300
```

This enforces:
| Condition              | Result         |
| ---------------------- | -------------- |
| 3 failed sudo attempts | account LOCKED |
| Duration               | 5 minutes      |
| Mechanism              | pam_faillock   |



## Test Results

### Test 1 — Admin user (Vincent_bare)

![adminRight](images/adminRight.png)

### Test 2 — Dev user (Jules_fedit)

![dev1Rights](images/dev1Rights.png)
![dev2Rights](images/dev2Rights.png)

### Test 3 — Intern user (Ignacio_botella)

![internRights](images/internRights.png)

## Summary

| User            | Group       | Sudo Rights         | Lockout Policy |
| --------------- | ----------- | ------------------- | -------------- |
| Vincent_bare    | admin       | Full sudo           | Yes            |
| Jules_fedit     | dev         | mount + restart ssh | Yes            |
| Ignacio_botella | intern      | No sudo             | Yes            |



---

# 6.2 Fine-Grained Access

## Objectives
- Create directory `/opt/projects`
- Apply access control:
  - admin → **rwx**
  - dev → **rw**
  - intern → **r**
- Use **ACL** (more flexible than UNIX permissions)
- Apply **CIS-recommended umask (027)** system-wide
- Test each user's access

---

# 📁 Directory Creation & ACL Setup

We used ACLs instead of simple UNIX permissions because:
- multiple groups need different rights
- ACLs allow per-group and per-user fine-grained control
- they support inheritance for new files

Install ACL support:

```bash
sudo apt install -y acl
```

Create folder:

```bash
sudo mkdir -p /opt/projects
```


## ACL Configuration


### Script: `/scripts/01_users.sh`
```bash
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
```

## Verification

```bash
ls -ld /opt/projects
getfacl /opt/projects
```
![ls-ld](images/ls-ld.png)

We see :

# file: projects

```bash
user::rwx
group::rwx
group:admin:rwx
group:dev:rw-
group:intern:r-x
mask::rwx
other::---
```
![acl check](images/aclCheck.png)


## UMASK Configuration (CIS Benchmark)

Why change umask?

The default Ubuntu umask is 002, which allows group write access.
CIS Benchmark recommends 027 to enforce restrictive defaults:

- owner: rwx
- group: r-x
- others: ---

This prevents accidental exposure of files.

Applied in:

/etc/login.defs:

/etc/profile:


## Verification

We ran 
```bash
umask
```

Output:

![umask027](images/umask027.png)


## Access Tests

We switched to each user to test expected behavior.

### 1. Admin (Vincent_bare – admin)

Then create a file and write into it. 

![admin Acl Access](images/adminAclAccess.png)

Finally, we try to read the content of the file.

![admin Acl Access](images/adminAclAccess2.png)

### 2. Developer (Jules_fedit – dev)

We connect to the dev_role account which is Jules_fedit.

![dev Acl Access](images/devAclAccess.png)

We can’t acces to /opt/projects which is normal because we don”t have the execution permission.
Nevertheless, we can write and read a file.

![dev Acl Access](images/devAclAccess.png)



### 3. Intern (Ignacio_botella – intern)

![intern Acl Access](images/internAclAccess.png)



## Summary

| Role   | Expected | Actual           | OK                           |
| ------ | -------- | ---------------- | ---------------------------- |
| admin  | rwx      | rwx              | ✔️                           |
| dev    | rw       | rw on files only | ✔️                           |
| intern | r        | r only           | ✔️ (x added for read access) |

ACLs also inherit correctly for newly created files.



## Conclusion

ACLs provide the required fine-grained control that classic UNIX permissions cannot offer.

We:

Applied correct ACLs per group

Configured inheritance

Adjusted umask to CIS standard

Verified behavior for all users

---

# 6.3 SSH Hardening & Authentication Security

## Objectives
- Install and activate SSH
- Disable password authentication (keys only)
- Disable root login
- Move SSH to a non-standard port
- Allow only our 3 users
- Add legal banner message
- Harden cryptographic algorithms (Ciphers, MACs, KEX)
- Test connectivity and rejection

We follow:
- **CIS Benchmark 5.2.x**
- **ANSSI RGS** SSH recommendations

---

# 🛠️ SSH Installation & Activation

```bash
sudo apt install -y openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh


## SSH Key Generation (Client Side)

Example for user vincent.bare:

```bash
ssh-keygen -t ed25519 -C "vincent"
ssh-copy-id -p 2222 vincent.bare@<server-ip>
```
This creates:

- private key → ~/.ssh/id_ed25519
- public key → ~/.ssh/id_ed25519.pub


Then we manually checked:

```bash
cat ~/.ssh/authorized_keys
```

## SSH Server Configuration (Hardening)

Main file:
```
/etc/ssh/sshd_config
```

We modified the following settings:

# Port changed (security by reducing automated scans)
Port 2222

# Disable root login
PermitRootLogin no

# Disable password authentication
PasswordAuthentication no
ChallengeResponseAuthentication no

# Key-based authentication only
PubkeyAuthentication yes

# Allow only our 3 users
AllowUsers vincent.bare jules.fedit ignacio.botella

# Banner message
Banner /etc/issue.net

# Hardened Ciphers (ANSSI + CIS)
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

# Hardened MAC algorithms
MACs hmac-sha2-512,hmac-sha2-256

# Strong key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org


Why these choices?

- Port change → reduces automated scans
- PermitRootLogin no → CIS + ANSSI requirement
- PasswordAuthentication no → prevents brute force
- Hardened Ciphers/MAC/KEX → only modern crypto allowed
- AllowUsers → restricts attack surface

Apply changes:

```
sudo systemctl restart ssh
```

## Connectivity Tests

### 1. Test with SSH key (should work)

```
ssh -p 2222 vincent.bare@<server-ip>
```

Result:

- Banner appears
- Login accepted
- No password asked

### 2. Test without SSH key (must fail)

```
ssh -p 2222 ignacio.botella@<server-ip>
```
Result:

Permission denied (publickey).




### 3. Test with wrong user (blocked by AllowUsers)


```
ssh -p 2222 root@<server-ip>
```

Result:

Permission denied.

## Cryptographic Audit

We verified the active algorithms with:

- ssh -Q cipher
- ssh -Q mac
- ssh -Q kex

We confirmed only the hardened ciphers/MACs/KEX are enabled.

screen proov


## Summary

| Requirement          | Status |
| -------------------- | ------ |
| Key-based login only | ✔️     |
| No password login    | ✔️     |
| Root SSH disabled    | ✔️     |
| Custom port (2222)   | ✔️     |
| Banner configured    | ✔️     |
| Restricted users     | ✔️     |
| Strong cryptography  | ✔️     |
| Tests performed      | ✔️     |


---

# 6.4 Firewall & Intrusion Protection

## ✔️ Objectives
- Install and configure UFW
- Deny all inbound & outbound traffic by default
- Allow only essential ports and justify each one
- Enable UFW logging
- Install and configure Fail2Ban
- Ban after 3 failed SSH login attempts
- Ban duration: 10 minutes
- Provide proof of bans and unbans

This configuration aligns with:
- CIS Ubuntu Benchmark (Section 3.5)
- Principle of Least Privilege
- ANSSI firewall best practices

---

# 1. UFW Configuration

## Installation

```bash
sudo apt install -y ufw
```


## Default deny (CIS requirement)


```bash
sudo ufw default deny incoming
sudo ufw default deny outgoing
```
This ensures that no communication is allowed unless explicitly authorized.




## Allowed Ports (with justification)

We only opened the strictly necessary ports based on our needs.

| Port | Service           | Direction | Justification                                            |
| ---- | ----------------- | --------- | -------------------------------------------------------- |
| 2222 | SSH (custom port) | In/Out    | Needed for remote admin access (secure port)             |
| 53   | DNS               | Out       | Required for domain resolution (APT updates)             |
| 443  | HTTPS             | Out       | Required for downloading signing keys & security updates |


Commands used:

```bash
sudo ufw allow out 53
sudo ufw allow out 443
sudo ufw allow 2222/tcp
```


No other port is allowed
Conforms to “least privilege” principle



## Enable Logging

```bash
sudo ufw logging on
```

Logs can be viewed using:


```bash
sudo tail -f /var/log/ufw.log
```

## Activate UFW

```bash
sudo ufw enable
sudo ufw status verbose
```


## 2. Fail2Ban Configuration

## Installation

```bash
sudo apt install -y fail2ban
```

We created a persistent configuration file:
```bash
/etc/fail2ban/jail.local
```

```bash
[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 600
findtime = 600
```


This means:

- 3 failed login attempts → BAN
- Ban lasts 10 minutes (600 seconds)


## Start Fail2Ban

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
sudo fail2ban-client status sshd
```
## Fail2Ban Ban Test

We intentionally used a wrong password from an unauthorized SSH attempt:

```bash
ssh -p 2222 wronguser@<server-ip>
```

After 3 attempts, the IP is banned:


```bash
sudo fail2ban-client status sshd
```



## Summary

| Component                                       | Status |
| ----------------------------------------------- | ------ |
| UFW installed & active                          | ✔️     |
| Deny all inbound/outbound                       | ✔️     |
| Only essential ports allowed with justification | ✔️     |
| Logging enabled                                 | ✔️     |
| Fail2Ban installed                              | ✔️     |
| SSH jail active                                 | ✔️     |
| Ban after 3 attempts                            | ✔️     |
| 10 min ban duration                             | ✔️     |
| Proof of ban/unban captured                     | ✔️     |


---

# 6.5 Data Encryption & Protection

## Objectives
- Create a 10–20 MB encrypted partition using **LUKS**
- Use `cryptsetup` to format & unlock the encrypted device
- Mount it at `/mnt/secure`
- Restrict access so only **admins** can see the content
- Demonstrate:
  - Mounted → data accessible  
  - Unmounted → data unreadable  
- Install and use **VeraCrypt**
- Create a **hidden volume** and store sensitive data in it

This follows:
- CIS Ubuntu Benchmark (Disk Encryption)
- ANSSI recommendations on data-at-rest protection

---

# 1. LUKS Encrypted Volume

## 1.1 Create a 20MB test partition

We simulate a storage device using a loopback file:

```bash
sudo dd if=/dev/zero of=/secure.img bs=1M count=20
sudo losetup /dev/loop10 /secure.img
```
<img width="1288" height="254" alt="image" src="https://github.com/user-attachments/assets/dc559fe1-a9c9-43a4-b348-07bddc189563" />


Check:

```bash
losetup -a
```
<img width="856" height="294" alt="image" src="https://github.com/user-attachments/assets/de160e42-517d-4cb5-b3f0-d24485a34848" />

## 1.2 Encrypt the volume with LUKS

```bash
sudo cryptsetup luksFormat /dev/loop10
```
Confirm with YES and set a passphrase.
<img width="1120" height="500" alt="image" src="https://github.com/user-attachments/assets/bebcc95a-05a6-4211-a61d-72dd9bd07df0" />


## 1.3 Open (unlock) the encrypted container


```bash
sudo cryptsetup open /dev/loop10 secure_volume
```
<img width="1096" height="160" alt="image" src="https://github.com/user-attachments/assets/a99ef377-896b-4269-b65a-1fbc38ff5420" />

## 1.4 Create a filesystem

```bash
sudo mkfs.ext4 /dev/mapper/secure_volume
```
<img width="1384" height="438" alt="image" src="https://github.com/user-attachments/assets/3f117485-048b-433f-ba03-1463ab5e9d75" />

## 1.5 Mount the encrypted volume

```bash
sudo mkdir -p /mnt/secure
sudo mount /dev/mapper/secure_volume /mnt/secure
```
<img width="1166" height="268" alt="image" src="https://github.com/user-attachments/assets/e352cc6c-52ae-4146-849c-c0b1f71c9934" />

# 2. Permissions & Access Control

```bash
sudo chown root:admin_role /mnt/secure
sudo chmod 770 /mnt/secure
```
<img width="820" height="282" alt="image" src="https://github.com/user-attachments/assets/8088348f-8f3b-44a8-a4d9-4ebfb0dbf44b" />

Meaning:

- Only root + admin_role have access
- Dev and intern cannot read/write

# 3. Demonstration of Encryption

```bash
sudo touch /mnt/secure/secret.txt
sudo echo "TOP SECRET" > /mnt/secure/secret.txt
cat /mnt/secure/secret.txt
```
Result: file is readable.

## 3.1 Mounted → data accessible

```bash
sudo echo "TOP SECRET" > /mnt/secure/secret.txt
cat /mnt/secure/secret.txt
```
<img width="1106" height="294" alt="image" src="https://github.com/user-attachments/assets/b7884a32-8670-42a7-b90a-32dbe03d7c22" />

## 3.2 Unmount and lock the volume

```bash
sudo umount /mnt/secure
sudo cryptsetup close secure_volume
```

Trying to access the file:


```bash
sudo cat /mnt/secure/secret.txt
```
<img width="1198" height="446" alt="image" src="https://github.com/user-attachments/assets/ab2270ca-7f27-4335-ab69-9f26749fc5ed" />

Result:

No such file or directory

Proof that encryption works.
Without unlocking (cryptsetup open), the data is unreadable.


# 4. VeraCrypt (Graphical + CLI)

We installed VeraCrypt:

```bash
sudo apt install veracrypt -y
```
<img width="1167" height="184" alt="image" src="https://github.com/user-attachments/assets/2a431505-184b-4de9-a83f-f8f7d9ba4de4" />

## 4.1 Create a VeraCrypt encrypted container

Steps

- Choose standard volume
- AES encryption
- 10–20MB size
- Set outer volume password

Using the GUI or CLI:
<img width="1073" height="860" alt="image" src="https://github.com/user-attachments/assets/f514edf1-1b75-4f8c-a15d-561980235d79" />

<img width="1214" height="814" alt="image" src="https://github.com/user-attachments/assets/473e528b-7cb1-41ee-9e10-c0f5fdfeb591" />

<img width="1205" height="793" alt="image" src="https://github.com/user-attachments/assets/d701d2b5-3bea-4088-a51b-addf8c1aea1a" />

<img width="1214" height="822" alt="image" src="https://github.com/user-attachments/assets/4b1b5497-d8bd-4d34-b558-b5cd6f373a0c" />

<img width="1203" height="811" alt="image" src="https://github.com/user-attachments/assets/29d3361a-d9e3-49ba-ab65-5ee0dddbd973" />

We need to move the mouse to generate entropy.

<img width="1209" height="797" alt="image" src="https://github.com/user-attachments/assets/eadd9a18-105a-4a28-b18c-d5f43a50dfc8" />

We are required to enter our password.

<img width="1216" height="798" alt="image" src="https://github.com/user-attachments/assets/b41ccf91-0202-4759-8299-5d5c3c20804d" />

<img width="1210" height="809" alt="image" src="https://github.com/user-attachments/assets/f8436152-3cce-4ab7-8911-6aebead52c73" />

As we could see, the volume has been scanned and the maximum volume has been successfully created.

<img width="1216" height="618" alt="image" src="https://github.com/user-attachments/assets/c0204361-2ba9-4b90-83b3-02dfd7331f1f" />


# 5. Summary

| Operation                  | Status |
| -------------------------- | ------ |
| LUKS volume created        | ✔️     |
| LUKS encryption validated  | ✔️     |
| Mounted/unmounted test     | ✔️     |
| Access restricted to admin | ✔️     |
| VeraCrypt installed        | ✔️     |
| Standard volume created    | ✔️     |
| Hidden volume created      | ✔️     |
| Sensitive data stored      | ✔️     |


---

# 6.6 Audit System

## Objectives
- Install and enable **auditd**
- Create persistent audit rules
- Track modifications or access attempts on:
  - `/etc/passwd`
  - `/etc/shadow`
  - `/root/*`
  - privileged commands: `sudo`, `passwd`, `mount`
- Generate logs for suspicious actions
- Provide proof using `ausearch` and `aureport`

This follows:
- CIS Benchmark (Section 4.1)
- ANSSI recommendations for critical file auditing

---

# 1. Installation & Activation

```bash
sudo apt install -y auditd audispd-plugins
sudo systemctl enable auditd
sudo systemctl start auditd
sudo systemctl status auditd
```

# 2. Audit Rules (Persistent)

We created the persistent rules file:

```bash
sudo nano /etc/audit/rules.d/hardening.rules
```

Contents:

```bash
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
```

Explanation of permission flags:

- r → read
- w → write
- a → attribute changes
- x → execution


# 3. Apply and Load the Rules

```bash
sudo auditctl -R /etc/audit/rules.d/hardening.rules
sudo auditctl -l
```

# 4. Trigger Events (Proof)

We performed multiple actions to generate audit logs.

## 4.1 Modify /etc/passwd (simulated)

```bash
sudo passwd testuser
```

## 4.2 Attempt to read /etc/shadow

```bash
sudo cat /etc/shadow
```

## 4.3 Execute privileged commands

```bash
sudo ls
```

passwd :


```bash
sudo passwd Vincent_bare
```

# 5. Summary Reports

We used aureport to generate summary tables:

```bash
sudo aureport -k
sudo aureport -x
sudo aureport -f
```

These outputs confirm that:
- executions are logged
- modifications are recorded
- forbidden accesses appear in the log

# Summary

| Feature                            | Status |
| ---------------------------------- | ------ |
| auditd installed                   | ✔️     |
| audit rules persistent             | ✔️     |
| passwd & shadow monitored          | ✔️     |
| privileged commands monitored      | ✔️     |
| root directory monitored           | ✔️     |
| events successfully triggered      | ✔️     |
| ausearch + aureport logs collected | ✔️     |

Our audit subsystem now ensures full traceability of sensitive file modifications and privileged actions, complying with CIS and ANSSI monitoring guidelines.
