# WatchGuard to Cisco ASA Migration Checklist

## 1. Overview
This technical checklist provides network engineers with an actionable, item-by-item guide for migrating enterprise network security policies, address objects, NAT translations, VPN tunnels, and administrative controls from **WatchGuard Firebox (Fireware OS)** to **Cisco Adaptive Security Appliance (ASA 5500-X / Firepower ASA Software)**.

---

## 2. Pre-Migration Discovery & Mapping Phase

### 2.1 Interface & Security Zone Translation
- [ ] Export WatchGuard network interface inventory (`Network -> Interfaces` in Fireware Web UI or WSM Policy Manager).
- [ ] Map WatchGuard interface types to Cisco ASA interface parameters:
  - External Interface $\rightarrow$ Cisco ASA `nameif outside` (Security Level 0)
  - Trusted Interface $\rightarrow$ Cisco ASA `nameif inside` (Security Level 100)
  - Optional Interface $\rightarrow$ Cisco ASA `nameif dmz` (Security Level 50)
  - Custom Interface $\rightarrow$ Cisco ASA `nameif <custom>` (Custom Security Level)
- [ ] Review WatchGuard VLAN sub-interfaces (802.1Q) and prepare Cisco ASA sub-interface definitions (`interface GigabitEthernet0/1.100` with `vlan 100`).
- [ ] Document primary IP addresses, secondary IP addresses, and IP aliases on WatchGuard interfaces.
- [ ] Map WatchGuard dynamic interface settings (DHCP client on WAN, PPPoE) to corresponding ASA syntax.

### 2.2 Address Objects and Aliases
- [ ] Export WatchGuard Host, Network, and FQDN objects.
- [ ] Inventory built-in WatchGuard Aliases (`Any-Trusted`, `Any-Optional`, `Any-External`, `Firebox`):
  - *Gotcha Warning*: WatchGuard `Firebox` refers to the firewall itself; in Cisco ASA, traffic terminating on the firewall is governed by `control-plane` policies or implicit listeners, whereas transit traffic requires explicit access-lists.
- [ ] Reformat WatchGuard IP ranges (`192.0.2.100 - 192.0.2.150`) into Cisco ASA `range` objects:
  ```cisco
  object network obj-range-dhcp
   range 192.0.2.100 192.0.2.150
  ```
- [ ] Standardize network naming: convert WatchGuard spaces/special characters into clean hyphenated tokens (`obj-net-finance`).

---

## 3. Security Policy & Access Control Translation

### 3.1 Policy Engine Architectural Differences
- [ ] WatchGuard separates traffic inspection into **Packet Filters** (Layer 3/4 stateful inspection) and **Proxy Policies** (Layer 7 application proxies such as HTTP-proxy, HTTPS-proxy, DNS-proxy, SMTP-proxy).
- [ ] Map WatchGuard Proxy Policies to Cisco ASA **Modular Policy Framework (MPF)** application inspection (`inspect http`, `inspect dns`, `inspect icmp`).
- [ ] Review WatchGuard HTTPS Content Inspection (DPI/TLS proxy):
  - If outbound SSL decryption was performed on WatchGuard, determine whether Cisco ASA with Firepower Services or dedicated web security gateways will terminate TLS inspection.

### 3.2 Access-List Syntax Conversion
- [ ] Translate WatchGuard Policy list into Cisco ASA extended access-lists:
  ```cisco
  access-list OUTSIDE_IN extended permit tcp any object obj-srv-web-dmz eq 443
  access-list OUTSIDE_IN extended deny ip any any log interval 300
  ```
- [ ] Bind access-lists to ingress interfaces using access-groups:
  ```cisco
  access-group OUTSIDE_IN in interface outside
  ```
- [ ] Account for Cisco ASA security-level traffic flow:
  - By default, traffic from higher security level (e.g., inside 100) to lower security level (e.g., outside 0) is permitted without an inbound ACL.
  - Inbound traffic from lower to higher security level is denied unless explicitly permitted in the access-list.
- [ ] If inter-zone communication between interfaces with equal security levels is required, enable:
  ```cisco
  same-security-traffic permit inter-interface
  ```

---

## 4. NAT / PAT (Network Address Translation) Translation

### 4.1 1-to-1 NAT (Inbound Server Publishing)
- [ ] WatchGuard 1-to-1 NAT maps external public IPs directly to internal private server IPs.
- [ ] Translate to Cisco ASA Auto-NAT (Object NAT):
  ```cisco
  object network obj-srv-web-internal
   host 198.51.100.10
   nat (dmz,outside) static 203.0.113.10
  ```

### 4.2 Dynamic NAT / Outbound Hide PAT
- [ ] WatchGuard uses dynamic NAT for trusted networks exiting the external interface.
- [ ] Translate to Cisco ASA dynamic interface PAT:
  ```cisco
  object network obj-net-inside-lan
   subnet 192.0.2.0 255.255.255.0
   nat (inside,outside) dynamic interface
  ```

### 4.3 Policy NAT / Twice NAT (VPN Exemption)
- [ ] On WatchGuard, VPN traffic bypasses 1-to-1 NAT automatically.
- [ ] On Cisco ASA, you MUST configure an identity NAT (Twice NAT rule 0) to exempt VPN traffic from dynamic outbound PAT:
  ```cisco
  nat (inside,outside) source static obj-net-inside-lan obj-net-inside-lan destination static obj-net-remote-branch obj-net-remote-branch no-proxy-arp route-lookup
  ```

---

## 5. Site-to-Site IPsec VPN Translation

- [ ] Export WatchGuard Branch Office VPN (BOVPN) settings.
- [ ] Map Phase 1 (IKEv2 SA) proposals:
  - WatchGuard: Encryption (AES-256), Hash (SHA2-256), Diffie-Hellman Group (Group 14).
  - Cisco ASA:
    ```cisco
    crypto ikev2 policy 10
     encryption aes-256
     integrity sha256
     group 14
     prf sha256
     lifetime seconds 86400
    ```
- [ ] Map Phase 2 (IPsec SA) proposals:
  - WatchGuard: ESP-AES256-GCM or ESP-AES256-SHA256.
  - Cisco ASA:
    ```cisco
    crypto ipsec ikev2 ipsec-proposal PROPOSAL_AES256_GCM
     protocol esp encryption aes-gcm-256
     protocol esp integrity null
    ```
- [ ] Configure Cisco ASA Tunnel Group and Pre-Shared Key:
  ```cisco
  tunnel-group 203.0.113.10 type ipsec-l2l
  tunnel-group 203.0.113.10 ipsec-attributes
   ikev2 remote-authentication pre-shared-key [SECRET]
   ikev2 local-authentication pre-shared-key [SECRET]
  ```

---

## 6. Pre-Cutover Validation Checklist

- [ ] Run automated policy validator:
  ```bash
  python scripts/pre-migration-validator.py --rules tests/sample-firewall-rules.csv --strict
  ```
- [ ] Run static security audit on candidate ASA config:
  ```bash
  bash scripts/asa-hardening-audit.sh -i templates/asa-baseline.conf -f json
  ```
- [ ] Test out-of-band management connectivity to new ASA.
- [ ] Backup legacy WatchGuard configuration (`.xml` workspace and `.wpk` image).
- [ ] Prepare rollback playbook (`scripts/rollback-checklist.yml`).

