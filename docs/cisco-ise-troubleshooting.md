# Cisco ISE Troubleshooting Guide: AAA, RADIUS & Policy Evaluation

## 1. Authentication and Authorization Flow Overview

Cisco Identity Services Engine (ISE) acts as the central Policy Decision Point (PDP), while network infrastructure devices (Cisco ASA, Catalyst switches, Wireless LAN Controllers) operate as Policy Enforcement Points (PEPs).

```
+------------+               +---------------+               +-----------------+
|   Client   |   (802.1X)    | Network Device|    (RADIUS)   |    Cisco ISE    |
| Endpoint   | <===========> |  (ASA/Switch) | <===========> |   (Policy Node) |
+------------+               +---------------+               +-----------------+
                                                                     |
                                                       +-------------+-------------+
                                                       |                           |
                                                       v                           v
                                              [ Active Directory ]       [ Certificate PKI ]
```

### Protocol Steps:
1. **Access-Request**: PEP sends RADIUS Access-Request packet (UDP port 1812) containing User-Name, Calling-Station-Id, NAS-IP-Address, and EAP-Message.
2. **Authentication Phase (Who are you?)**:
   - ISE matches incoming request against **Policy Sets** based on conditions (e.g. Device Type, Location, Wired/Wireless).
   - ISE selects the configured **Authentication Policy** and queries the Identity Source (Internal Users, Active Directory, or Certificate Authentication Profile).
3. **Authorization Phase (What are you allowed to do?)**:
   - Upon successful credential/certificate verification, ISE evaluates **Authorization Rules** (top-down, first-match).
   - Rules combine identity attributes, posture state, and profiling data.
4. **Access-Accept / Access-Reject**:
   - ISE transmits RADIUS Access-Accept containing attributes: dACLs, Security Group Tags (SGT), or Authorization Profiles (VLAN assignment, session timeouts).

---

## 2. RADIUS Communication & Connectivity Troubleshooting

### 2.1 Packet Transport & Port Verification
RADIUS communication uses standard UDP ports:
- **Authentication & Authorization**: UDP 1812 (legacy RFC 2138: UDP 1645)
- **Accounting**: UDP 1813 (legacy RFC 2139: UDP 1646)
- **CoA (Change of Authorization)**: UDP 1700 / RFC 5176 UDP 3799

### 2.2 Verifying Connectivity from Network Device (Cisco ASA)
```cisco
# Test direct authentication from ASA to ISE node
test aaa-server authentication ISE_RADIUS host 192.0.2.60 username secadmin password <PW>

# Check server statistics and timeout counters
show aaa-server ISE_RADIUS
```
- **Symptom: Server Marked DEAD**: If the ASA fails to receive a response within `timeout` * `retry-interval`, it marks the ISE node DEAD.
  - *Fix*: Check routing, transit ACLs on intermediate firewalls permitting UDP 1812/1813, and verify shared secret agreement.

---

## 3. Live Logs and Failure Reason Codes

The primary tool for diagnosing ISE authentication is the **Live Logs** viewer:
*ISE GUI -> Operations -> RADIUS -> Live Logs*

### Common Failure Reason Codes in ISE:

| Failure Reason Code | Root Cause | Remediation Procedure |
| :--- | :--- | :--- |
| **5400 Authentication failed** | Invalid credentials, bad password, or account locked in AD. | Verify user account status in Active Directory; reset password. |
| **5411 EAP handshake failed** | Client terminated SSL handshake or rejected server cert. | Verify client trusts the ISE EAP authentication certificate authority. |
| **5440 Endpoint abandoned EAP** | Network timeout or supplicant closed session prematurely. | Check wireless RF signal, switch 802.1X timeout timers (`dot1x timeout tx-period`). |
| **86000 RADIUS Shared Secret Mismatch** | Shared secret configured in ASA `aaa-server` does not match ISE Network Device entry. | Re-enter shared secret exactly on both ASA and ISE Network Device configuration. |
| **106015 Authorization failed** | User passed authentication, but no authorization rule matched, or dACL failed to download. | Inspect Authorization Policy logic and check dACL syntax. |

---

## 4. Authorization Profiles & Dynamic Network Assignment

When ISE authorizes an endpoint, it delivers operational instructions via standard and vendor-specific attributes (VSAs):
- **VLAN Assignment**:
  - `Tunnel-Type = 13` (VLAN)
  - `Tunnel-Medium-Type = 6` (802)
  - `Tunnel-Private-Group-Id = <VLAN_ID_or_NAME>`
- **Downloadable ACL (dACL)**:
  - Transmitted via Cisco VSA `cisco-av-pair = "ip:inacl#1=permit..."`.
  - Must adhere strictly to Cisco ACL syntax; any syntax error causes the access switch/firewall to reject the entire policy and quarantine the port.

---

## 5. Structured Troubleshooting Workflow

Follow this 5-step triage progression:

```
[ Step 1: Physical & L3 Reachability ]
  -> Ping ISE IP from ASA/Switch management interface.
  -> Verify UDP 1812/1813 are open across intermediate gateways.

[ Step 2: Shared Secret Verification ]
  -> Re-key the RADIUS secret on both PEP and ISE to eliminate typographical discrepancies.

[ Step 3: Inspect ISE Live Logs ]
  -> Navigate to Operations > RADIUS > Live Logs. Click the magnifying glass on the failed event.
  -> Check the "Detailed Authentication Report" to identify the failing sub-step.

[ Step 4: Supurce Identity Verification ]
  -> Verify Active Directory join status in ISE (Administration > Identity Management > External Identity Sources).
  -> Execute AD diagnostic test tool from ISE GUI.

[ Step 5: Policy Set Logic Review ]
  -> Review condition logic: Ensure device groups, subnets, and identity groups match incoming packet attributes.
```

