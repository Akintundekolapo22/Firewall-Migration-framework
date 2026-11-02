# Troubleshooting Case Study: Cisco ISE EAP-TLS Authentication Failure via SAN Identity Mismatch

## 1. Scenario Background and Incident Overview

### Environment Architecture
- **Enterprise Network**: Corporate Headquarters LAN, Cisco Catalyst 9300 access switch operating as IEEE 802.1X Authenticator.
- **Identity Provider**: Cisco Identity Services Engine (ISE 3.2), Active Directory Domain Controller (`corp.example`).
- **PKI Infrastructure**: Microsoft Active Directory Certificate Services (AD CS) Enterprise Two-Tier PKI (Offline Root CA + Online Issuing Enterprise Sub-CA).
- **Client Endpoint**: Windows 11 Enterprise Corporate Laptop (`ws-eng-042.corp.example`), authenticated via Machine 802.1X prior to user logon.

### Problem Statement
Following the rollout of a refreshed workstation machine certificate template in AD CS (modernized to enforce RFC 5280 SAN extensions and omit deprecated Subject DN formatting), all newly provisioned engineering laptops suddenly fail wired 802.1X network authentication upon plugging into corporate access ports. The switch port falls back to the restricted guest VLAN or remains completely unauthenticated (`Unauthorized`).

---

## 2. Initial Triage and Symptom Collection

### 2.1 Switch Port Status (Cisco Catalyst CLI)
```cisco
switch-hq-access# show authentication sessions interface GigabitEthernet1/0/12 details
            Interface:  GigabitEthernet1/0/12
          MAC Address:  0050.56a1.2b3c
         IPv4 Address:  Unknown
            User Name:  host/ws-eng-042.corp.example
               Status:  Unauthorized
               Domain:  DATA
       Security Policy:  Should Secure
       Security Status:  Unsecure
        Oper host mode:  single-host
      Oper control dir:  both
         Session timeout: N/A
          Restart timeout: N/A
    Common Session ID:  0A0002FE0000003B2A10C99B
      Acct Session ID:  0x00000042
               Handle:  0x6B00003C
       Current Policy:  POLICY_Gi1/0/12

Method status list:
       Method           State
        dot1x           Failed over
          mab           Stopped
```
- **Observation**: The 802.1X method enters `Failed over`, causing the port to remain `Unauthorized`.

---

## 3. Root Cause Investigation in Cisco ISE

### 3.1 Inspecting ISE RADIUS Live Logs
Navigate to *Operations -> RADIUS -> Live Logs*. Locate the failed authentication attempt corresponding to MAC `00:50:56:A1:2B:3C`:

- **Event Status**: Failed (Red Cross icon)
- **Failure Reason**: `22056 Subject not found in the identity store`
- **Resolution**: `Verify that the user or host exists in the external identity store.`

Clicking the magnifying glass icon reveals the **Detailed Authentication Report**:

```
Steps:
11001  Received RADIUS Access-Request
11017  RADIUS packet contains EAP-Message
11514  Prepared EAP-Request/Identity
11516  Received EAP-Response/Identity: host/ws-eng-042.corp.example
22016  Selected Certificate Authentication Profile: CAP_Default_Subject_CN
22037  Beginning TLS handshake with client
12500  Extracted Certificate details from ClientHello
12502  Client certificate verified against trusted Enterprise Root CA
22055  Extracting identity using Certificate Authentication Profile: [CAP_Default_Subject_CN]
       Certificate Subject: [Empty or O=Corp, C=US]
       Certificate Subject Alternative Name (SAN:DNS): [ws-eng-042.corp.example]
22056  Subject not found in the identity store. Extracted username is NULL or empty string.
11504  Prepared RADIUS Access-Reject
```

### 3.2 Root Cause Analysis
1. The enterprise PKI template stopped populating the `Subject: CN` field with the computer hostname, setting it to a generic organizational unit (`O=Corp, C=US`) while placing the actual Fully Qualified Domain Name into the **Subject Alternative Name (`SAN: DNS`)** extension (`ws-eng-042.corp.example`).
2. Cisco ISE was configured with a legacy **Certificate Authentication Profile (CAP)** set to extract the principal identity strictly from `Subject - Common Name (CN)`.
3. Because the `CN` attribute was empty or lacked the hostname, ISE extracted a `NULL` identity string.
4. When ISE queried Active Directory for a computer account matching `NULL`, the search returned zero results, triggering failure code `22056` and an immediate `Access-Reject`.

---

## 4. Step-by-Step Remediation Procedure

### Step 4.1: Update Certificate Authentication Profile (CAP) in Cisco ISE
1. Log into the Cisco ISE Admin Portal.
2. Navigate to: **Administration -> Identity Management -> External Identity Sources -> Certificate Authentication Profiles**.
3. Select the active profile: `CAP_Corporate_Machines` (or create a new profile).
4. Under **Principal Username**:
   - Change radio button from `Subject - Common Name` to **`Subject Alternative Name`**.
   - Set the dropdown attribute selector to **`DNS`** (or `Other Name -> User Principal Name (UPN)` for user certificates).
5. Check the box: **"Never strip domain from username"** (or configure appropriate domain suffix mapping).
6. Click **Save**.

```
+---------------------------------------------------------------------------------------------+
| Cisco ISE Certificate Authentication Profile Settings                                       |
+---------------------------------------------------------------------------------------------+
| Name                 : CAP_Corporate_Machines_Modernized                                    |
| Description          : Modern RFC 5280 SAN DNS extraction for machine 802.1X                |
| Identity Attribute   : [x] Subject Alternative Name                                         |
| SAN Attribute Type   : [x] DNS Name                                                         |
| Identity Store       : ActiveDirectory: corp.example                                        |
+---------------------------------------------------------------------------------------------+
```

### Step 4.2: Update the Authentication Policy in ISE Policy Sets
1. Navigate to: **Policy -> Policy Sets -> Default (or Wired 802.1X Policy Set)**.
2. Expand the **Authentication Policy** section.
3. Locate the rule matching wired 802.1X machine authentication.
4. Under **Use / Allowed Protocols**, ensure `Default Network Access` (with EAP-TLS enabled) is selected.
5. Under **Identity Source**, ensure the updated Certificate Authentication Profile (`CAP_Corporate_Machines_Modernized`) is selected.
6. Click **Save**.

---

## 5. Verification and Validation

### 5.1 Clear the Authentication Session on Switch
On the access switch, bounce the interface or clear the session cache:
```cisco
switch-hq-access# clear authentication sessions interface GigabitEthernet1/0/12
```

### 5.2 Validate Switch Session State
```cisco
switch-hq-access# show authentication sessions interface GigabitEthernet1/0/12 details
            Interface:  GigabitEthernet1/0/12
          MAC Address:  0050.56a1.2b3c
         IPv4 Address:  192.0.2.145
            User Name:  ws-eng-042.corp.example
               Status:  Authorized
               Domain:  DATA
       Security Policy:  Should Secure
       Security Status:  Secure
        Oper host mode:  single-host
      Oper control dir:  both
         Session timeout: 28800s
    Common Session ID:  0A0002FE0000003B2A10C99B
       Current Policy:  POLICY_Gi1/0/12

Method status list:
       Method           State
        dot1x           Authc Success

Assigned Attributes:
        VLAN ID:        10 (CORP_SECURE_DATA)
        dACL Name:      DACL_ENGINEERING_STANDARD
```

### 5.3 Validate Detailed Report in ISE Live Logs
Refresh *Operations -> RADIUS -> Live Logs*. The entry now displays a **Green Checkmark**:
- **Event Status**: Success
- **Identity**: `ws-eng-042.corp.example`
- **Extracted From**: `Certificate SAN:DNS`
- **Active Directory Match**: `CN=WS-ENG-042,OU=Workstations,DC=corp,DC=example`
- **Authorization Result**: `VLAN 10, DACL_ENGINEERING_STANDARD, Access-Accept`

---

## 6. Preventive Governance & Key Architectural Takeaways

1. **Avoid Hardcoding Subject CN in Identity Policies**: Always configure Certificate Authentication Profiles to inspect `SAN:DNS` for computers and `SAN:UPN` for users.
2. **Standardize Certificate Templates**: When authoring AD CS Certificate Templates, ensure the `Subject Name` tab is configured to build identity information directly from Active Directory attributes (DNS Name and UPN).
3. **Staged PKI Rollouts**: When renewing or refreshing CA certificate templates, always validate against pilot endpoints before pushing certificates enterprise-wide via Group Policy.

