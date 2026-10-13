# DLP & Secure File Transfer Monitor

Defensive, user-space file-transfer auditing for **systems you own or are authorized to monitor**.

## 1. Setup

```bash
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt                         # just: watchdog>=4.0.0
```

Create a lab to try it safely:

```bash
mkdir -p ~/dlp_lab/{sensitive,approved,usb_sim,downloads,work}
echo "Q3 payroll: confidential" > ~/dlp_lab/sensitive/payroll.csv
```

## 2. Configure (`config.json`)

| Key | Meaning |
|---|---|
| `sensitive_dirs` | Protected folders. Every file inside is hashed into a baseline. |
| `approved_destinations` | The only places sensitive files may be copied/moved to. Anything else is a violation. |
| `watch_dirs` | Extra folders to watch (mount points, shares, staging areas). Sensitive dirs are watched automatically. |
| `removable_media_roots` / `network_share_roots` | Used to label `dest_type` in alerts (USB, share). On Windows add drive letters (`"E:\\"`) and UNC prefixes. |
| `download_dirs` / `upload_staging_dirs` | Files appearing here are logged as `DOWNLOAD` / `UPLOAD_QUEUED`. |
| `sensitive_modification_severity` | Severity when a sensitive file's content changes (`INFO/WARNING/HIGH/CRITICAL`). |
| `log_all_events` | `false` = log only sensitive-file activity (less noise). |
| `ignore_patterns` | Filename globs to skip (editor lock files). Avoid ignoring `*.tmp`; renaming is an easy evasion. |

## 3. Run

```bash
python dlp_monitor.py -c config.json            # start monitoring (Ctrl+C stops and writes a report)
python dlp_monitor.py -c config.json --report   # build security_report.txt from existing logs
python dlp_monitor.py -c config.json --rebuild-baseline   # accept current files as the trusted state
```

Outputs:
- `security_audit.log` - human-readable, real-time audit trail (`tail -f security_audit.log`)
- `audit_events.jsonl` - same events as JSON, one per line (for SIEM ingestion / scripting)
- `sensitive_baseline.json` - trusted SHA-256 per sensitive file (detects changes made while the monitor was off)
- `security_report.txt` - summary report

Try the scenarios from another terminal:

```bash
cd ~/dlp_lab
cp sensitive/payroll.csv approved/backup.csv       # authorized copy      -> INFO
cp sensitive/payroll.csv usb_sim/payroll.csv       # unauthorized copy    -> CRITICAL
head -c 10 sensitive/payroll.csv > work/payroll.csv   # truncated copy    -> CRITICAL INTEGRITY_FAILURE
echo "x" >> sensitive/payroll.csv                  # tampering            -> HIGH
mv sensitive/payroll.csv work/notes.txt            # renamed + moved out  -> CRITICAL
```

## 4. Example output (captured from a real run)

**Sensitive file copied to an unapproved location**
```
>>> ALERT 2026-10-12 14:13:26 | CRITICAL | UNAUTHORIZED_COPY        | src=/tmp/lab/sensitive/payroll.csv | dst=/tmp/lab/usb/payroll.csv | dest_type=REMOVABLE_MEDIA | sha256_before=ea38e339...a641b7 | sha256_after=ea38e339...a641b7 | integrity=PASS | policy=sensitive file sent to a destination not in approved_destinations
```

**Integrity failure (copy does not match the original)**
```
>>> ALERT 2026-10-12 14:13:28 | CRITICAL | INTEGRITY_FAILURE        | src=/tmp/lab/sensitive/customers.db | dst=/tmp/lab/usb/customers.db | sha256_before=3b101006...015ca6d2 | sha256_after=f1a8847b...a6d011f4 | note=hash mismatch after transfer - corrupted, truncated or tampered
```

**Tampering with a sensitive file**
```
>>> ALERT 2026-10-12 14:13:30 | HIGH     | SENSITIVE_FILE_MODIFIED  | src=/tmp/lab/sensitive/customers.db | sha256_before=3b101006...015ca6d2 | sha256_after=a6f62c90...5656912f1 | note=content changed - possible tampering
```

**Authorized copy**
```
2026-10-12 14:13:24 | INFO     | AUTHORIZED_COPY          | src=/tmp/lab/sensitive/payroll.csv | dst=/tmp/lab/approved/payroll_backup.csv | ... | integrity=PASS
```

**Move out of the sensitive area (copy + delete of original, correlated)**
```
>>> ALERT ... | CRITICAL | UNAUTHORIZED_COPY | src=.../sensitive/payroll.csv | dst=.../work/notes.txt | dest_type=LOCAL_DISK | ...
>>> ALERT ... | CRITICAL | MOVE_CORRELATED   | src=.../sensitive/payroll.csv | dst=.../work/notes.txt | note=copy followed by deletion of original = MOVE
```

## 5. Event reference

| Event | Severity | Meaning |
|---|---|---|
| `AUTHORIZED_COPY/MOVE` | INFO | Destination is approved |
| `UNAUTHORIZED_COPY/MOVE` | CRITICAL | Destination not approved (`dest_type` shows USB / share / local) |
| `MOVE_CORRELATED` | INFO/CRITICAL | Original deleted shortly after a copy, so it was really a move |
| `INTEGRITY_FAILURE` | CRITICAL/HIGH | Pre- and post-transfer SHA-256 differ, or file changed while monitor was offline |
| `SENSITIVE_FILE_MODIFIED` | configurable | Baseline hash no longer matches |
| `SENSITIVE_FILE_DELETED` / `_MISSING` | HIGH | Tracked file removed |
| `INTERNAL_MOVE/COPY`, `NEW_SENSITIVE_FILE` | INFO | Activity inside sensitive tree |
| `DOWNLOAD`, `UPLOAD_QUEUED`, `FILE_ACTIVITY` | INFO | Non-sensitive activity |

## 6. How detection works, and its limits

- **Copies** are inferred: a new file whose SHA-256 matches a baseline file is a copy. A new file with the *same name but different hash* is flagged as a possible corrupted/tampered transfer (a heuristic, so expect occasional false positives).
- **Moves between separately watched folders** surface as create+delete, so the tool correlates them within `move_correlation_seconds`.
- **No attribution**: watchdog cannot tell you *which user or process* did it. For that, pair this with OS auditing (Linux `auditd`, Windows Event ID 4663 / Sysmon, macOS Endpoint Security).
- **Scope**: it sees only watched paths, and only local filesystem effects. It does not inspect network traffic, so "upload" means a file staged in `upload_staging_dirs`.
- **Content changes only**: renaming a file and copying it somewhere is still caught (hash match), but an exfiltrated *modified* file with a different name is not.
- Single worker thread keeps event order simple; hashing very large files delays later events. Fine for audits, not for high-volume servers.
- Keep the log and baseline files somewhere only admins can write (or ship the JSONL to a SIEM) so an insider cannot edit the evidence.
