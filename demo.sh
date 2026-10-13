#!/usr/bin/env bash
# demo.sh - runs every DLP scenario with captions and pauses, for screen recording.
# Run from a SECOND terminal while the monitor + dashboard services are running.
# Usage: bash demo.sh
set -u
LAB="$HOME/dlp_lab"
PAUSE=5   # seconds between steps (lets the dashboard refresh and the viewer read)

step() {            # step "caption" "command"
  echo
  echo "=== $1"
  echo "\$ $2"
  sleep 2
  eval "$2"
  sleep "$PAUSE"
}

cd "$LAB" || { echo "missing $LAB"; exit 1; }
[ -f sensitive/payroll.csv ] || { echo "sensitive/payroll.csv missing - run the reset first"; exit 1; }

echo "DLP demo starting. Watch the dashboard at http://127.0.0.1:8080"
sleep 4

step "1. Authorized copy to an approved folder (INFO)" \
     "cp sensitive/payroll.csv approved/backup.csv"
step "2. Unauthorized copy to removable media (CRITICAL)" \
     "cp sensitive/payroll.csv usb_sim/payroll.csv"
step "3. Truncated / corrupted copy (INTEGRITY_FAILURE)" \
     "head -c 10 sensitive/payroll.csv > work/payroll.csv"
step "4. Tampering with the sensitive file (HIGH)" \
     "echo 'tampered' >> sensitive/payroll.csv"
step "5. Renamed and moved out of the sensitive folder (CRITICAL)" \
     "mv sensitive/payroll.csv work/notes.txt"

echo
echo "Demo finished. Reset before recording again (see the reset commands)."
