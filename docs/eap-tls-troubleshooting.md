# EAP-TLS Troubleshooting Guide: Public Key Infrastructure & 802.1X

## 1. EAP-TLS Architecture & Authentication Handshake

Extensible Authentication Protocol - Transport Layer Security (EAP-TLS, RFC 5216) provides mutual cryptographic certificate-based authentication between endpoint supplicants and authentication servers (Cisco ISE).

```
+------------+                  +---------------+                  +-----------------+
| Supplicant |                  | Authenticator |                  | Authentication  |
|  (Client)  |                  | (ASA/Switch)  |                  |  Server (ISE)   |
+------------+                  +---------------+                  +-----------------+
      |                                 |                                   |
      |------- EAPOL-Start ------------>|                                   |
      |<------ EAP-Request/Identity ----|                                   |
      |------- EAP-Response/Identity -->|-------- RADIUS Access-Request --->|
      |                                 |<------- RADIUS Access-Challenge --|
      |<------ EAP-Request/TLS Start ---|                                   |
      |------- EAP-Response/ClientHello>|-------- RADIUS Access-Request --->|
      |                                 |<------- RADIUS Access-Challenge --|
      |<------ EAP-Request/ServerHello,-|                                   |
      |        Certificate, etc. -------|                                   |
      |------- ClientCertificate, ----->|-------- RADIUS Access-Request --->|
      |        ClientKeyExchange, etc. -|                                   |
      |                                 |<------- RADIUS Access-Accept -----|
      |<------ EAP-Success -------------|                                   |
```

---

## 2. Key Failure Domains and Diagnostics

### 2.1 Mutual Certificate Trust and Chain Completeness
Both parties must establish a cryptographically unbroken chain of trust:
- **Server Trust by Client**: The client OS (Windows Cert Store / macOS Keychain) must contain the Root CA and all Intermediate Issuing CAs that signed the Cisco ISE EAP certificate.
- **Client Trust by ISE**: ISE's *Trusted Certificate Store* (*Administration -> System -> Certificates -> Trusted Certificates*) must contain the Root CA and Intermediate CAs that issued user or machine certificates.
- **Intermediate Chain Omission**: If an Intermediate CA is absent from the trust store, the handshake fails immediately with `Unknown CA` or `Certificate Chain Incomplete`.

### 2.2 Certificate Validity, Dates and Time Synchronization (NTP)
- **Clock Drift**: A discrepancy of more than 5 minutes between the client workstation, Cisco ASA, and Cisco ISE node will cause certificates to be evaluated as `Not Yet Valid` or `Expired`.
- **System Time Check**:
  - Cisco ISE CLI: `show clock` and `show ntp`
  - Cisco ASA CLI: `show clock` and `show ntp status`
  - Supplicant Workstation: Synchronize via Active Directory domain controller or RFC 5905 NTP server.

### 2.3 Identity Extraction and Subject Alternative Name (SAN) Matching
- ISE extracts user/computer identities based on the **Certificate Authentication Profile (CAP)**.
- If the CAP is configured to read the identity from `Subject - Common Name (CN)` but the enterprise PKI populates the identity solely in `Subject Alternative Name - User Principal Name (SAN:UPN)`, identity resolution returns empty, resulting in immediate authentication failure.
- **Remediation**: Configure ISE Certificate Authentication Profile to match:
  - For Users: `Principal Name (SAN)`
  - For Computers: `DNS Name (SAN)` or `CN`

### 2.4 Private-Key Availability and Permissions
- The client endpoint must possess the private key corresponding to the public certificate.
- On Windows systems, inspect with `certmgr.msc` or `certlm.msc`:
  - Ensure the key icon appears on the certificate: *"You have a private key that corresponds to this certificate."*
  - Ensure Cryptographic Service Provider (CSP) or Key Storage Provider (KSP) permissions allow the `SYSTEM` / `NetworkService` account read access if performing machine-based authentication.

### 2.5 Certificate Revocation Checking (CRL and OCSP)
- When ISE receives the client certificate, it evaluates revocation status via:
  - **Certificate Revocation Lists (CRL)**: HTTP / LDAP distribution points.
  - **Online Certificate Status Protocol (OCSP)**: Real-time HTTP responder.
- **Failure Mode - Fail-Closed**: If ISE's Trusted Certificate entry has *CRL / OCSP Verification* set to `Require`, and the firewall blocks ISE's outbound HTTP request to the internal PKI distribution point, ISE aborts the handshake with `Revocation Status Unknown`.
- **Remediation**: Check proxy and firewall rules permitting ISE to contact CRL Distribution Points (CDP).

---

## 3. Distinguishing Authentication vs. Authorization Failures

| Attribute | Authentication Failure (AuthN) | Authorization Failure (AuthZ) |
| :--- | :--- | :--- |
| **Point of Failure** | EAP-TLS cryptographic handshake or identity lookup. | Post-handshake policy matching or dACL / VLAN binding. |
| **ISE Live Log Icon** | Red cross (Failed authentication). | Yellow warning or red cross with "Authorization Failed". |
| **RADIUS Packet** | `Access-Reject` transmitted to switch/firewall. | `Access-Accept` with restricted attributes or `Access-Reject`. |
| **Log Message** | "EAP-TLS handshake failed", "Bad certificate", "Unknown CA". | "No authorization rule matched", "Downloadable ACL syntax error". |
| **Troubleshooting Target** | PKI trust stores, certificate expiration, SAN attributes, client supplicant config. | ISE Authorization Rules, Active Directory group memberships, dACL syntax. |

---

## 4. Remediation Checklist for Common EAP-TLS Defects

1. **Supplicant Rejects ISE Certificate**:
   - Push enterprise Root CA to client machines via Active Directory Group Policy (GPO) or MDM (Intune / Jamf).
   - Verify the server certificate Subject Alternative Name matches the FQDN configured in the client's 802.1X profile.
2. **ISE Rejects Supplicant Certificate**:
   - Check ISE Live Logs: Click the detailed record to see the OpenSSL error code (e.g., `SSL alert number 48: unknown CA`).
   - Import missing intermediate enterprise certificates into ISE's Trusted Certificate store and mark the checkbox **"Trust for client authentication"**.
3. **Machine vs. User Auth Confusion**:
   - For domain laptops prior to user login, the Windows supplicant must be configured for **"Computer authentication"** or **"User or computer authentication"**.

