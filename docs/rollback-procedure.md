# Enterprise Firewall Rollback Procedure

## 1. Objectives & Safety Architecture

The rollback workflow provides a safe, deterministic, and auditable mechanism to revert firewall state following an unrecoverable failure during a migration maintenance window.

### Safety Design Tenets
1. **Never Execute Destructive Actions by Default**:
   - The Ansible automation enforces `rollback_approved: false` as the immutable baseline default.
   - Any invocation without `-e rollback_approved=true` terminates immediately prior to making any configuration changes.
2. **Mandatory Backup Verification**:
   - The backup configuration file must exist as a readable, non-empty regular file on disk.
3. **Traceable Audit Ledger**:
   - Every invocation (whether simulated or live) writes an immutable event entry to `reports/sample/rollback-audit.log`.

---

## 2. Pre-Requisites and Recovery Artifacts

Before commencing cutover or rollback, ensure the following artifacts are confirmed:

- **Baseline Golden Config**: Exported running configuration stored at `data/sample/backup.cfg`.
- **Administrative Access**: Out-of-band serial console or dedicated OOB management IP connectivity confirmed.
- **Change Reference**: Active Change Ticket ID (e.g. `CHG-0089214`).
- **Designated Recovery Authority**: Name of the Lead Network Security Engineer authorizing the reversion.

---

## 3. Rollback Execution Workflows

### 3.1 Mode A: Safe Lab Simulation (Default)
In lab environments or when executing dry-run tests without physical Cisco hardware:

```bash
ansible-playbook ansible/rollback.yml \
  -e "rollback_approved=true" \
  -e "simulation_mode=true" \
  -e "backup_file_path=data/sample/backup.cfg" \
  -e "firewall_hostname=fw-edge-01.corp.example"
```

**Simulation Steps Performed:**
1. Validates that `backup_file_path` exists and parses critical security tokens (`interface`, `hostname`, `access-list`).
2. Confirms variable requirements without modifying local or remote system state.
3. Records audit log entry in `reports/sample/rollback-audit.log`.
4. Executes simulated reachability verification.

### 3.2 Mode B: Physical Device Restoration (Production Cutover)
For live appliances with the `cisco.asa` collection installed and direct network_cli connectivity:

```bash
ansible-playbook ansible/rollback.yml \
  -i ansible/inventory.ini.example \
  -e "rollback_approved=true" \
  -e "simulation_mode=false" \
  -e "backup_file_path=data/sample/backup.cfg" \
  -e "firewall_hostname=fw-edge-01.corp.example"
```

**Hardware Restoration Steps:**
1. Validates inventory target and credentials via Ansible Vault.
2. Asserts explicit rollback approval.
3. Pushes baseline configuration to the Cisco ASA appliance using `cisco.asa.asa_config` with atomic replacement or differential staging.
4. Executes operational reachability checks to target IP (`192.0.2.1`).

---

## 4. Manual Fallback Procedure (Out-of-Band Console)

If automated Ansible connectivity fails due to management plane impairment, execute manual recovery via the serial console:

```cisco
! 1. Enter privileged EXEC mode
enable

! 2. Clear corrupted candidate running-config
configure terminal
clear configure access-list
clear configure route

! 3. Copy baseline backup from TFTP or local flash
copy disk0:/backup-golden.cfg running-config

! 4. Verify interfaces and routes
show interface ip brief
show ip route

! 5. Commit baseline to non-volatile startup storage
write memory
```

---

## 5. Post-Recovery Verification Checklist

Following rollback completion:
1. Ping default gateway and internal core switches (`192.0.2.1`).
2. Verify BGP adjacency is re-established: `show bgp summary`.
3. Verify remote syslog forwarding: `show logging`.
4. Verify RADIUS / TACACS+ AAA server reachability: `show aaa-server`.
5. Run static security audit against restored config:
   ```bash
   bash scripts/asa_security_audit.sh -i data/sample/backup.cfg
   ```
6. Update Change Ticket record with recovery logs and timestamp.

