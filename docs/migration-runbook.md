# Firewall Migration Runbook

## 1. Scope, Objectives and Assumptions

### 1.1 Scope
This runbook governs the planned cutover of perimeter and data center firewalls from legacy hardware (e.g., Cisco ASA 5500-X series) to target appliances (e.g., Cisco Firepower FPR-2100 running ASA image or refreshed ASA platforms).

### 1.2 Assumptions & Prerequisites
- All migration manifests have passed automated offline semantic validation (`scripts/firewall_precheck.py`).
- Target appliances are racked, cabled, power-tested, and reachable over an out-of-band management network.
- Target firmware versions match enterprise approved release baselines (e.g., ASA 9.18.x Interims).
- The maintenance window has been formally approved by the Change Advisory Board (CAB).

---

## 2. Discovery and Dependency Review

1. **Adjacent Device Mapping**:
   - Upstream WAN transit ISP routers (BGP peering IP, AS numbers, MD5 auth keys).
   - Downstream core switches (802.1Q trunks, port channels, default gateways).
2. **Stateful Services Review**:
   - IPsec / AnyConnect VPN sessions (notify remote workforce of session termination).
   - Active NAT translations and dynamic PAT port pools.
   - Cisco ISE TACACS+ / RADIUS policy bindings.
3. **Bandwidth & Cable Verification**:
   - Verify optical transceiver compatibility (1G SFP vs 10G SFP+ vs 25G SFP28).
   - Ensure patch cables are pre-labeled with source and destination interface IDs.

---

## 3. Pre-Migration Configuration Backup & Preservation

Before changing any physical or logical state:

```bash
# Capture full running and startup configurations on legacy firewall
terminal length 0
show version
show running-config
show startup-config
show crypto ikev2 sa
show vpn-sessiondb summary
show ip route
show arp
copy running-config tftp://192.0.2.50/backup-legacy-fw01-precutover.cfg
```

Store this backup locally at `data/sample/backup.cfg` to serve as the emergency rollback baseline.

---

## 4. Pre-Cutover Validation Phase (T - 2 Hours)

Execute the automated pre-migration validator against the target staging manifest:

```bash
python scripts/firewall_precheck.py \
  --input data/sample/migration-valid.json \
  --output reports/sample/migration-validation-report.json \
  --strict
```

### Exit Criteria
- If `firewall_precheck.py` returns exit code `2`, the change **MUST NOT PROCEED**.
- Reconcile invalid CIDRs, conflicting interface IPs, or unresolvable ACL objects before opening the maintenance window.

---

## 5. Migration Execution Sequence (Maintenance Window)

| Step | Time | Action | Responsible | Command / Procedure |
| :--- | :--- | :--- | :--- | :--- |
| **5.1** | T-00:00 | Change Window Open | Lead Engineer | Bridge call joined; notify NOC & SOC. |
| **5.2** | T+00:05 | Suppress Monitoring Alerts | NOC | Mute SolarWinds / Datadog / PRTG alerts for target host. |
| **5.3** | T+00:10 | Disable Dynamic Routing on Legacy | Lead Engineer | `router bgp <ASN>` -> `neighbor <PEER> shutdown` |
| **5.4** | T+00:15 | Shutdown Legacy Physical Interfaces | Network Eng | `interface range G0/0 - 3` -> `shutdown` |
| **5.5** | T+00:20 | Cable Cutover to Target Firewall | Datacenter Ops | Move pre-labeled patch cords to new appliance. |
| **5.6** | T+00:25 | Apply Staged Config on Target Firewall| Lead Engineer | Load sanitized baseline template (`templates/asa/asa-base.cfg`). |
| **5.7** | T+00:30 | Unshut Interfaces on Target Firewall | Lead Engineer | `no shutdown` on `outside`, `inside`, `dmz`. |
| **5.8** | T+00:35 | Activate BGP Edge Routing | Lead Engineer | `neighbor <PEER> no shutdown` |

---

## 6. Post-Migration Operational Verification

Perform progressive layer-by-layer validation:

```bash
# 1. Physical and Data Link Layer
show interface ip brief

# 2. Routing Convergence
show ip route
show bgp summary
show ip bgp neighbors 203.0.113.1 summary

# 3. Security ACL & Connection Inspection
show access-list OUTSIDE_IN
show conn count
show nat

# 4. Centralized Authentication & Logging
test aaa-server authentication ISE_SERVERS host 192.0.2.60 username secadmin password <TEST_PW>
show logging
```

Execute an offline hardening audit against the new running-config:

```bash
bash scripts/asa_security_audit.sh -i /path/to/target-running.cfg -o reports/sample/post-mig-audit.txt
```

---

## 7. Failure Criteria & Rollback Decision Matrix

### 7.1 Failure Trigger Conditions
A rollback decision MUST be made if any of the following occur:
1. **Critical Route Failure**: Inability to establish BGP peering with WAN providers within 20 minutes of cutover.
2. **Core Blackholing**: Sustained packet drop rate > 2% across internal core subnets for more than 15 minutes.
3. **Management Isolation**: Total loss of out-of-band management connectivity to target appliance.
4. **Hard Cutoff Time**: Maintenance window reaches T - 45 minutes without successful traffic restoration.

### 7.2 Rollback Execution Sequence
If rollback is triggered:
1. Incident Commander announces: *"ABORT CHANGE. INITIATING ROLLBACK PROTOCOL."*
2. Re-cable patch cords back to legacy firewall ports.
3. Re-enable legacy interfaces: `no shutdown`.
4. Restore BGP peering: `neighbor <PEER> no shutdown`.
5. Execute automated rollback verification playbook:
   ```bash
   ansible-playbook ansible/rollback.yml -e "rollback_approved=true simulation_mode=false"
   ```
6. Verify service restoration on legacy firewall.
7. Notify stakeholders and close change window as `ROLLED_BACK`.

---

## 8. Communication and Change-Record Protocol

- **T - 24h**: Reminder email sent to business unit application owners.
- **T - 15m**: Pre-call bridge setup (NOC, Security Operations, Infrastructure Lead).
- **T + Finish**: Post-migration summary broadcast:
  - Total downtime incurred.
  - Verification test results.
  - Audit report attachment.
- **T + 24h**: Post-Implementation Review (PIR) meeting held to review metric logs and retire change ticket.

