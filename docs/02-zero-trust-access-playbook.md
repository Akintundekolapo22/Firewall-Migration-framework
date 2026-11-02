# Zero Trust Access Playbook: Identity-Based Network Access Control

## 1. Zero Trust Architecture and Cisco ISE

Zero Trust Network Architecture (ZTNA, NIST SP 800-207) asserts that no endpoint, user, or device inside or outside the enterprise perimeter should be granted implicit trust. Cisco Identity Services Engine (ISE) serves as the centralized **Policy Decision Point (PDP)**, dynamically evaluating identity, device posture, and context before instructing **Policy Enforcement Points (PEPs)** (such as Cisco ASA firewalls, Catalyst switches, and Wireless LAN Controllers) to grant least-privilege network access.

```
+---------------------------------------------------------------------------------------------------------+
|                                    ZERO TRUST CONTROL & DATA PLANES                                     |
+---------------------------------------------------------------------------------------------------------+
                                                     |
         +-------------------------------------------+-------------------------------------------+
         |                                           |                                           |
         v                                           v                                           v
[ Endpoint Supplicant ]                   [ Enforcement Point (PEP) ]                 [ Policy Decision (PDP) ]
  - Machine / User Cert                     - Cisco ASA / Catalyst Switch               - Cisco ISE 3.x
  - 802.1X Supplicant                       - 802.1X Authenticator                      - RADIUS (1812) / TACACS+ (49)
  - EAP-TLS Handshake                       - Dynamic VLAN / dACL / SGT                 - Policy Sets & Posture
```

---

## 2. Authentication Protocols: RADIUS vs. TACACS+

| Feature | RADIUS (RFC 2865 / RFC 2866) | TACACS+ (RFC 8907) |
| :--- | :--- | :--- |
| **Primary Use Case** | Network Access Control (802.1X, EAP-TLS, VPN users) | Device Administrative Access (SSH CLI, Enable commands) |
| **Transport Layer** | UDP (Port 1812 Auth, 1813 Acct) | TCP (Port 49) |
| **AAA Separation** | Combines Authentication & Authorization | Strictly separates Authentication, Authorization & Accounting |
| **Packet Encryption** | Encrypts password only (Packet headers cleartext) | Encrypts entire packet payload |
| **Command Authorization**| Coarse (VLAN, dACL, Session-Timeout) | Per-command authorization (granular command-by-command filtering) |

---

## 3. IEEE 802.1X Wired Network Access & EAP-TLS

### 3.1 Mutual Cryptographic Authentication Handshake
IEEE 802.1X with EAP-TLS (RFC 5216) provides the gold standard for zero trust identity because it relies on asymmetric public-key cryptography rather than vulnerable shared passwords or pre-shared keys.

1. **EAPOL-Start**: Supplicant initiates authentication upon link-state up on switch/firewall port.
2. **EAP-Request/Identity**: Authenticator requests endpoint identity.
3. **EAP-Response/Identity**: Supplicant responds with anonymous identity or user/machine identity.
4. **TLS Tunnel Negotiation**: Supplicant and Cisco ISE exchange TLS ClientHello and ServerHello, negotiating cipher suites (e.g. `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`).
5. **Server Authentication**: Cisco ISE presents its EAP server certificate. Supplicant validates the trust chain back to the enterprise Root CA.
6. **Client Authentication**: Supplicant presents its machine or user certificate. Cisco ISE validates the trust chain back to the enterprise Issuing CA and performs revocation checking (CRL / OCSP).
7. **Identity Extraction & Authorization**: ISE maps certificate attributes to Active Directory / LDAP groups and delivers an `Access-Accept` with authorization attributes (dACL, VLAN, or SGT).

---

## 4. Identity Extraction: Common Name (CN) vs. Subject Alternative Name (SAN)

Modern operating systems, browser engines, and identity providers have deprecated reliance on the certificate `Subject Common Name` (RFC 6125, RFC 5280).

### 4.1 The Divergence
- **Subject Common Name (`Subject: CN=...`)**: Legacy attribute originally intended for human-readable names. Often truncated or missing in modern multi-domain or cloud-managed PKI deployments.
- **Subject Alternative Name (`SAN:DNS` or `SAN:UPN`)**: Modern, cryptographically rigorous extension supporting multiple domain names, IP addresses, and user principal names (`user@corp.example`).

### 4.2 Certificate Authentication Profile (CAP) Matching Rules in ISE
In Cisco ISE (*Administration -> Identity Management -> External Identity Sources -> Certificate Authentication Profiles*):

```
+---------------------------------------------------------------------------------------------+
| Certificate Attribute | Recommended Identity Resolution | Enterprise Use Case               |
+---------------------------------------------------------------------------------------------+
| SAN: OtherName (UPN)  | Direct Principal Resolution     | Corporate Domain Users            |
| SAN: DNS Name         | Host Identity Matching          | Corporate Laptops & Servers       |
| Subject: CN           | Fallback Only                   | Legacy Non-Compliant Devices      |
+---------------------------------------------------------------------------------------------+
```

---

## 5. Structured Troubleshooting Progression for Authentication Failures

When an endpoint fails 802.1X authentication, follow this 4-step diagnostic progression:

### Step 1: Physical Link and 802.1X State Check (Authenticator CLI)
```cisco
show authentication sessions interface GigabitEthernet1/0/5 details
```
- Look for `Status: Unauthorized`, `EAP Method: N/A`, or `Auth Type: None`.
- If link stays in `HELD` state, verify supplicant service is running on endpoint (`Wired AutoConfig` service on Windows).

### Step 2: RADIUS Packet Flow & Shared Secret Verification
```cisco
test aaa-server authentication ISE_SERVERS host 192.0.2.60 username testadmin password <SECRET>
show aaa-server ISE_SERVERS
```
- If packets timeout, verify UDP 1812/1813 are permitted across intermediate firewalls and that the RADIUS shared secret matches exactly.

### Step 3: Cisco ISE Live Logs & OpenSSL Failure Codes
Navigate to *Operations -> RADIUS -> Live Logs*. Click the magnifying glass on the failed event to inspect the detailed failure report:
- **5400 Authentication failed**: Bad password or account locked.
- **5411 EAP handshake failed**: Handshake aborted due to untrusted certificate.
- **5434 Radius packet contains invalid attribute**: Malformed VSA or dictionary mismatch.
- **86000 RADIUS shared secret mismatch**: Key mismatch between PEP and ISE.

### Step 4: Certificate Revocation and Clock Skew
- Verify NTP synchronization across endpoint, switch, and ISE: `show ntp status`.
- Check if ISE can reach the CRL Distribution Point (CDP) or OCSP responder over HTTP. If CRL check fails and revocation policy is set to `Require`, ISE drops the authentication.

