# Enterprise Firewall Migration Methodology

## Executive Summary
This document establishes a standardized, five-phase enterprise methodology for migrating mission-critical perimeter and datacenter firewalls from legacy appliances (such as WatchGuard Firebox running Fireware OS) to modern enterprise firewall platforms (such as Cisco ASA 5500-X / Firepower appliances operating ASA software).

---

## 1. Five-Phase Migration Lifecycle

```
+---------------------------------------------------------------------------------------------------------+
|                                    ENTERPRISE MIGRATION LIFECYCLE                                       |
+---------------------------------------------------------------------------------------------------------+
       |
       v
[ Phase 1: Discovery & Assessment ]
  -> Interface topologies, VLAN tagging, static/dynamic routes, IPsec VPN tunnels, NAT translation rules.
       |
       v
[ Phase 2: Policy Review & Optimization ]
  -> Rule base rationalization, shadow rule elimination, dead object pruning, zero-trust mapping.
       |
       v
[ Phase 3: Configuration & Pre-Migration Validation ]
  -> Translation to Cisco ASA syntax, offline semantic validation, CIDR checks, automated schema pre-check.
       |
       v
[ Phase 4: Deployment, Cutover & Verification ]
  -> Maintenance window execution, interface cutover, BGP convergence, progressive 5-layer verification.
       |
       v
[ Phase 5: Post-Migration Monitoring & Rollback Readiness ]
  -> 72-hour burn-in telemetry, syslog SIEM monitoring, configuration baseline commit, rollback readiness.
```

---

### Phase 1: Network Discovery and Infrastructure Assessment

#### 1.1 Physical and Logical Topology Mapping
- Document all physical interfaces, speeds, duplex, and medium (Copper RJ-45 vs. Multi-Mode/Single-Mode SFP+ transceivers).
- Map 802.1Q sub-interfaces and corresponding VLAN IDs on adjacent core/distribution switches.
- Inventory Layer 3 addressing, secondary IP addresses, and Virtual Router Redundancy Protocol (VRRP/HSRP) configurations.

#### 1.2 Routing and Transit Discovery
- Ingress and egress default gateways.
- Dynamic routing peering sessions (BGP, OSPF, EIGRP), Autonomous System Numbers (ASNs), peer IPs, MD5 authentication keys, timers, and route filtering policies.
- Static and policy-based routes (PBR).

#### 1.3 Stateful Network Services & Translation
- NAT/PAT tables: Static one-to-one NATs (DMZ public services), dynamic PAT pools (outbound employee internet egress), and policy/twice NAT rules.
- Site-to-site IPsec VPN configurations: Phase 1 IKE proposals, Phase 2 IPsec proposals, Pre-Shared Keys, remote peer IPs, and interesting traffic access-lists/proxy IDs.
- Client-to-gateway VPN (SSL/AnyConnect vs. IKEv2 Mobile VPN).
- DHCP relay helpers and local server pools.

---

### Phase 2: Security Policy Review and Migration Planning

#### 2.1 Rule Base Normalization
Legacy firewall policies accumulate years of temporary permits, obsolete vendors, and duplicate rules. Prior to migration:
1. **Dormant Rule Pruning**: Identify rules with zero hit counts over 90+ days.
2. **Duplicate Rule Elimination**: Consolidate redundant access control entries across identical 5-tuples.
3. **Shadow Rule Resolution**: Analyze rules where broader upstream rules mask specific downstream permits or denies.
4. **Any-Any Mitigation**: Convert generic `permit ip any any` rules into discrete object-based rules adhering to zero-trust principles.

#### 2.2 Naming Convention Standard
Establish uniform object naming:
- Network Objects: `obj-net-<vlan/desc>-<subnet>` (e.g., `obj-net-finance-192.0.2.0-24`)
- Host Objects: `obj-host-<hostname/role>` (e.g., `obj-host-ise-primary`)
- Service Objects: `obj-svc-<proto>-<port>` (e.g., `obj-svc-tcp-443`)
- Access Lists: `<INGRESS_ZONE>_<EGRESS_ZONE>_ACL` (e.g., `OUTSIDE_INSIDE_ACL`)

---

### Phase 3: Configuration Development and Pre-Migration Validation

#### 3.1 Automated Pre-Migration Policy Validation
Run `scripts/pre-migration-validator.py` against the exported CSV policy set to detect:
- Duplicate rules.
- Fully or partially shadowed access rules.
- Overly permissive security rules.
- Invalid CIDR or unroutable host IP configurations.
- Exposed administrative ports from untrusted zones.

```bash
python scripts/pre-migration-validator.py \
  --rules tests/sample-firewall-rules.csv \
  --output examples/migration-risk-report.json \
  --strict
```

#### 3.2 Offline Security Hardening Audit
Verify the generated Cisco ASA candidate configuration using `scripts/asa-hardening-audit.sh` against NIST SP 800-53 and CIS Benchmarks:

```bash
bash scripts/asa-hardening-audit.sh -i templates/asa-baseline.conf -f json -o reports/sample/asa-audit-report.json
```

---

### Phase 4: Firewall Deployment, Migration, and Verification

#### 4.1 Maintenance Window Sequence (T-0 to T+90 minutes)

| Sequence | Elapsed | Action Item | Verification Command |
| :--- | :--- | :--- | :--- |
| **4.1.1** | T-00:00 | Change window declared open; NOC/SOC bridge activated. | Bridge attendance confirmed. |
| **4.1.2** | T-00:05 | Suppress automated monitoring alerts for firewall endpoints. | SolarWinds / PRTG muted. |
| **4.1.3** | T-00:10 | Capture final running-config and ARP table from legacy firewall. | `show arp`, `show ip route` |
| **4.1.4** | T-00:15 | Gracefully drain BGP / dynamic routing sessions on legacy unit. | `neighbor <IP> shutdown` |
| **4.1.5** | T-00:20 | Administratively shutdown physical interfaces on legacy unit. | `interface <if> shutdown` |
| **4.1.6** | T-00:25 | Physical cable transfer: move uplinks to new Cisco ASA. | Link state LEDs verified green. |
| **4.1.7** | T-00:30 | Unshut interfaces on Cisco ASA; activate candidate config. | `show interface ip brief` |
| **4.1.8** | T-00:35 | Bring up dynamic routing / BGP peering on Cisco ASA. | `show bgp summary` |
| **4.1.9** | T-00:45 | Perform progressive 5-layer post-migration verification. | Verification checklist executed. |
| **4.1.10**| T-01:00 | Business application test sign-offs (ERP, Web, Email). | Application owner confirmation. |

---

### Phase 5: Post-Migration Monitoring, Documentation, and Rollback Readiness

#### 5.1 72-Hour Burn-in Monitoring
- Monitor interface error counters (CRC, frame errors, overruns): `show interface GigabitEthernet0/0 | grep error`.
- Inspect drop counters and deny log rates in centralized SIEM.
- Validate NAT translation memory utilization: `show xlate count`.
- Confirm CPU and memory stability: `show cpu usage`, `show memory`.

#### 5.2 Commit and Archival
- Save running configuration to non-volatile memory: `write memory`.
- Export running configuration to secure configuration repository.
- Update network architecture diagrams and IP address management (IPAM) records.
- Hold Post-Implementation Review (PIR) to archive change ticket.

---

## 2. WatchGuard Fireware to Cisco ASA Migration Checklist

| Architectural Domain | WatchGuard Fireware Implementation | Cisco ASA Target Implementation | Migration Action & Gotchas |
| :--- | :--- | :--- | :--- |
| **Security Zones** | External, Trusted, Optional, Custom | `nameif` (outside, inside, dmz, mgmt) | Map each WatchGuard interface to explicit Cisco ASA `nameif`. |
| **Zone Trust Model** | Any-to-Any blocked unless allowed by Policy | Security Level 0 - 100 (`security-level`) | Higher level can reach lower level by default; inbound requires explicit ACL. |
| **Inter-Zone Traffic** | Handled strictly by policy rules | `same-security-traffic permit inter-interface` | ASA drops traffic between same security-level interfaces unless enabled. |
| **Policy Organization** | Proxy policies (HTTP-proxy) vs Packet Filters | Modular Policy Framework (MPF) + Access-Lists | WatchGuard deep-inspection proxies convert to MPF inspection classes. |
| **NAT Architecture** | 1-to-1 NAT, Dynamic NAT, Server Load Balancing | Auto-NAT (object NAT) & Manual/Twice NAT | WatchGuard 1-to-1 NAT converts to `nat (dmz,outside) static <IP>`. |
| **Address Groups** | Aliases (e.g. `Any-Trusted`, `Firebox`) | Network Object Groups (`object-group network`) | Expand WatchGuard dynamic aliases into concrete CIDR subnet objects. |
| **Site-to-Site VPN** | Branch Office VPN (BOVPN) Virtual Interfaces | Crypto Maps or VTI (Virtual Tunnel Interfaces) | WatchGuard Phase 1/2 proposals convert to `crypto ikev2` policies & proposals. |
| **Administrative Access** | Fireware Web UI (port 8080) & WSM (port 4118) | Cisco ASDM (HTTPS port 443) & SSH CLI (port 22) | Restrict ASDM/SSH strictly to dedicated management VLAN. |
| **Authentication** | Active Directory Auth, Firebox-DB | Cisco ISE / RADIUS (`aaa-server`) with local fallback | Bind AAA to console and enable: `aaa authentication ssh console`. |
| **Logging** | WatchGuard Dimension / Log Server | Syslog forwarding (`logging host <if> <ip>`) | Direct logs to corporate SIEM; enable `logging timestamp`. |

