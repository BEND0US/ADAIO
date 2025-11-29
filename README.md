# ADAIO

ADAIO is a standalone Active Directory enumeration and attack surface discovery tool.

It focuses on detecting commonly abused privilege escalation primitives and misconfigurations.

---

## Features

- AS-REP Roasting
- Kerberoasting
- Dangerous ACLs (GenericAll, WriteDacl, WriteOwner, ResetPassword, AddMember, GPO Abuse)
- Shadow Credentials (KeyCredentialLink)
- SIDHistory Injection
- Delegation Attacks (Unconstrained, Constrained, RBCD)
- LAPS (Legacy & v2) Unauthorized Readers
- DCSync Rights
- AdminSDHolder Misconfigurations
- GPP (cpassword) Detection
- ADCS ESC1, ESC2, ESC3, ESC4, ESC6
- Exchange & DNSAdmins Privilege Paths
- Domain Trust Analysis

---

## Usage

```powershell
.\ADAIO.ps1 -OutFile output -Format JSON
