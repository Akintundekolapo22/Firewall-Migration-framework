# Branch-Site Deployment & Migration Verification Template

## 1. Branch-Site Network Deployment Template

### 1.1 Branch Architecture Overview
This standard branch deployment blueprint is designed for distributed enterprise remote offices connecting to Corporate Headquarters and Cloud infrastructure over redundant WAN links (Dual ISP with BGP or IPsec failover).

```
+---------------------------------------------------------------------------------------------------------+
|                                  BRANCH SITE ARCHITECTURAL BLUEPRINT                                     |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                    +--------------------------------+--------------------------------+
                    |                                                                 |
                    v                                                                 v
         [ Primary WAN: ISP-A ]                                            [ Backup WAN: ISP-B ]
            203.0.113.0/29                                                    198.51.100.0/29
                    |                                                                 |
                    +--------------------------------+--------------------------------+
                                                     |
                                                     v
                                     [ Branch Perimeter Firewall ]
                                        Cisco ASA / Firepower 1010
                                                     |
                                                     v
                                       [ Branch Core/Access Switch ]
                                            Cisco Catalyst 1000
                                                     |
                      +------------------------------+------------------------------+
                      |                              |                              |
                      v                              v                              v
             [ VLAN 10: Data ]              [ VLAN 20: Voice ]             [ VLAN 30: Guest Wi-Fi ]
               192.0.2.0/25                   192.0.2.128/26                 192.0.2.192/26
```

---

### 1.2 Standard Subnet Allocation Blueprint (RFC 5737 De-identified)

| Network Segment | VLAN ID | Network CIDR | Usable Host Range | Default Gateway | Security Zone |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **WAN Primary (ISP-A)** | Untagged | 203.0.113.0/29 | 203.0.113.2 - 203.0.113.6 | 203.0.113.1 | `outside` (0) |
| **WAN Backup (ISP-B)** | Untagged | 198.51.100.0/29| 198.51.100.2 - 198.51.100.6 | 198.51.100.1 | `outside2` (0) |
| **Corporate Data** | VLAN 10 | 192.0.2.0/25 | 192.0.2.2 - 192.0.2.126 | 192.0.2.1 | `inside` (100) |
| **VoIP Telephony** | VLAN 20 | 192.0.2.128/26 | 192.0.2.130 - 192.0.2.190 | 192.0.2.129 | `voice` (100) |
| **Isolated Guest Wi-Fi** | VLAN 30 | 192.0.2.192/26 | 192.0.2.194 - 192.0.2.254 | 192.0.2.193 | `guest` (10) |
| **Out-of-Band Mgmt** | VLAN 99 | 192.0.2.64/27 | 192.0.2.66 - 192.0.2.94 | 192.0.2.65 | `management` (100) |

---

### 1.3 Pre-Deployment Staging Checklist (T - 7 Days)

- [ ] **Hardware Staging**: Appliance unboxed, serial numbers cataloged, asset tags applied.
- [ ] **Firmware Compliance**: Update Cisco ASA firmware to enterprise baseline (e.g., ASA 9.18.x Interim).
- [ ] **Cryptographic Initialization**: Generate 2048-bit or 4096-bit RSA master key:
  ```cisco
  crypto key generate rsa modulus 4096 noconfirm
  ```
- [ ] **Identity & AAA Configuration**: Pre-configure RADIUS pointing to enterprise Cisco ISE nodes (`192.0.2.60`).
- [ ] **Administrative Access**: Enable SSH v2; apply `ssh timeout 15` and `console timeout 15`.
- [ ] **Licensing**: Verify Base License, AnyConnect Apex/Plus licenses, and Strong Encryption (3DES/AES) entitlement.
- [ ] **Out-of-Band Access**: Confirm Cellular / LTE terminal server connectivity to serial console port.

---

## 2. Firewall Migration Operational Verification Checklist

Following cutover during the maintenance window, the lead engineer and network operations center must execute this progressive 5-layer verification checklist before signing off.

### Layer 1: Physical Link and Layer 2 Data Link
- [ ] Verify link LED status on all physical ports (outside, inside, dmz, management).
- [ ] Confirm interface duplex and speed negotiation:
  ```cisco
  show interface ip brief
  show interface GigabitEthernet0/0 | grep "duplex"
  ```
- [ ] Check for frame errors, collisions, and interface drops:
  ```cisco
  show interface GigabitEthernet0/0 | grep "error"
  ```

### Layer 2: Network Layer and Routing Adjacency
- [ ] Confirm Layer 3 interface IP assignments and status:
  ```cisco
  show ip address
  ```
- [ ] Test ICMP reachability to upstream ISP gateways:
  ```cisco
  ping outside 203.0.113.1
  ```
- [ ] Verify static default route presence:
  ```cisco
  show ip route | grep "0.0.0.0"
  ```
- [ ] Verify BGP edge routing neighbor state (`Established`):
  ```cisco
  show bgp summary
  show ip bgp neighbors
  ```

### Layer 3: Security Policy and State Table Inspection
- [ ] Verify access-list hit counters are actively incrementing:
  ```cisco
  show access-list OUTSIDE_IN
  ```
- [ ] Validate stateful connection table growth:
  ```cisco
  show conn count
  ```
- [ ] Validate dynamic outbound PAT translations:
  ```cisco
  show nat
  show xlate count
  ```

### Layer 4: VPN Tunnels & Remote Telephony
- [ ] Verify IKEv2 Security Associations with HQ / Datacenter:
  ```cisco
  show crypto ikev2 sa
  ```
- [ ] Verify IPsec Child SAs (Encapsulation and Decapsulation incrementing):
  ```cisco
  show crypto ipsec sa peer 203.0.113.10
  ```
- [ ] Validate VoIP SIP trunk registration across voice VLAN.

### Layer 5: Management, Telemetry & Application Sign-Off
- [ ] Test AAA authentication against Cisco ISE:
  ```cisco
  test aaa-server authentication ISE_RADIUS host 192.0.2.60 username testadmin password <PW>
  ```
- [ ] Confirm remote SIEM syslog forwarder is actively streaming events:
  ```cisco
  show logging
  ```
- [ ] Verify local workstation DNS resolution and outbound web access:
  ```powershell
  Resolve-DnsName -Name "intranet.corp.example"
  Test-NetConnection -ComputerName "203.0.113.10" -Port 443
  ```
- [ ] Confirm change ticket sign-off and close maintenance window.

