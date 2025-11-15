# Linux Security Hardening – ECE Paris – ING5 CYB  
### **Team: Vincent Baré – Jules Fedit – Ignacio Botella**  
### **Group: Gr03 – TP03**


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
