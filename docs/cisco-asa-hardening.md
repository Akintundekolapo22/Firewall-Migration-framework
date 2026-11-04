# Cisco ASA Security Hardening Guide

## Overview
This engineering guide provides practitioner-oriented security configuration baselines for Cisco ASA 5500-X and Firepower appliances operating ASA software, directly supporting Module 3 of the Firewall Migration Framework. Security controls and configuration recommendations are mapped to **NIST SP 800-53 Rev. 5** and the **CIS Cisco ASA Benchmark v4.1.0**, establishing reproducible, audit-ready security baselines for enterprise firewall modernization.

---

## 1. Management Plane Security

The management plane represents the primary target for malicious persistence and administrative interception. Hardening the management plane ensures that control traffic is strictly isolated from tenant and transit data planes.

### 1.1 Out-of-Band (OOB) Interface Isolation
- Bind administrative listeners exclusively to dedicated management interfaces tagged with `management-only`:
  ```cisco
  interface GigabitEthernet0/3
   nameif management
   security-level 100
   management-only
   ip address 192.0.2.254 255.255.255.0
  ```
- The `management-only` command prevents the interface from routing transit traffic, eliminating data-plane bleed into administrative networks.

### 1.2 Deprecation of Cleartext Protocols
- **Telnet**: Completely prohibited. Never issue `telnet <ip> <mask> <interface>`.
- **HTTP / ASDM**: If web GUI administration is mandatory, restrict listener strictly to bastion subnets. Never bind `http 0.0.0.0 0.0.0.0` or allow ASDM exposure on public/outside interfaces:
  ```cisco
  no http 0.0.0.0 0.0.0.0 outside
  http 192.0.2.64 255.255.255.224 management
  ```

---

## 2. SSH and Administrative Access Hardening

1. **Protocol Restriction**: Force SSH version 2 to prevent version-rollback attacks:
   ```cisco
   ssh version 2
   ```
2. **Access Control**: Enforce explicit CIDR masks for management subnets:
   ```cisco
   ssh 192.0.2.64 255.255.255.224 management
   ```
3. **Session Timeouts**: Mitigate unattended workstation takeover:
   ```cisco
   ssh timeout 15
   console timeout 15
   ```
4. **Modern Cryptographic Suites**: Require Diffie-Hellman Group 14+ key exchanges and disable weak 3DES/SHA-1 ciphers:
   ```cisco
   ssh key-exchange group dh-group14-sha256
   ssh cipher encryption aes256-ctr aes192-ctr aes128-ctr
   ```

---

## 3. Centralized AAA and Authentication Framework

1. **Primary Enterprise Authentication**: Configure RADIUS / TACACS+ server groups pointing to Cisco ISE or enterprise Identity Providers:
   ```cisco
   aaa-server ISE_RADIUS protocol radius
   aaa-server ISE_RADIUS (management) host 192.0.2.60
    key 8 <SHARED_SECRET>
    authentication-port 1812
    accounting-port 1813
   ```
2. **Fallback Mechanism**: Always define local fallback authentication to prevent administrative lockout during directory outages:
   ```cisco
   aaa authentication ssh console ISE_RADIUS LOCAL
   aaa authentication enable console ISE_RADIUS LOCAL
   ```
3. **Password Protection**:
   - Never use obsolete `enable password` (Type 0 plaintext or Type 7 reversible).
   - Use salted SHA-256/PBKDF2 hashes via `enable secret 8 <HASH>`.
   - Enable master AES passphrase encryption: `password encryption aes`.

---

## 4. Logging, Auditing & SIEM Integration

- **Centralized Forwarding**: Transmit all syslog events (severity levels 1 through 6) to a central SIEM collector:
  ```cisco
  logging enable
  logging timestamp
  logging buffer-size 131072
  logging buffered warnings
  logging host management 192.0.2.50
  logging facility 20
  ```
- **NTP Time Synchronization**: Forensics and event correlation require microsecond-accurate timestamps across firewalls and SIEM nodes:
  ```cisco
  ntp server 192.0.2.10 source management
  ```

---

## 5. Access Control Policy & Microsegmentation

- **Deny-by-Default Architecture**: Explicitly deny and log all unpermitted traffic at interface ingress boundaries:
  ```cisco
  access-list OUTSIDE_IN extended deny ip any any log interval 300
  ```
- **Prohibit Global Any-Any Permits**: Avoid generic `permit ip any any` rules on edge firewalls. Every rule must explicitly bind to verified network objects and destination service ports.
- **Strict Boundary Isolation**: Ensure `same-security-traffic permit inter-interface` is omitted unless explicitly required by hub-and-spoke VPN hair-pinning designs.

---

## 6. Version-Dependent Considerations & Modernization

| Cisco ASA Release | Hardening Capability / Syntax Change |
| :--- | :--- |
| **9.1(x) and older** | Lacked PBKDF2/SHA-512 `enable secret 8/9`. Deprecated. |
| **9.4(x) - 9.12(x)** | Introduced enhanced SSH cipher filtering (`ssh cipher encryption`). |
| **9.14(x) - 9.18(x)+**| TLS 1.3 support for ASDM / VPN; strict cipher deprecation for legacy 3DES/RC4. |

---

## 7. Static-Analysis Limitations

Offline static configuration auditing (such as `scripts/asa_security_audit.sh`) provides vital baseline governance, but has intrinsic boundaries:
- **Runtime State Ignored**: Cannot observe active routing table convergence, interface link flaps, or CPU utilization spikes.
- **Dynamic Policy Omission**: Cannot evaluate dynamic ACL entries injected by Cisco ISE via Downloadable ACLs (dACLs) or TrustSec Security Group Tags (SGTs).
- **Physical Cable Faults**: Cannot diagnose physical optical transceiver attenuation or SFP mismatch.
- **Recommendation**: Complement static offline audits with dynamic lab emulation and post-migration operational verification checklists.

