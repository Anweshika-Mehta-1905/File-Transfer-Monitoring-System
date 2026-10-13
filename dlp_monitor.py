#!/usr/bin/env python3
"""
dlp_monitor.py - Defensive DLP & Secure File Transfer Monitor
=============================================================
For AUTHORIZED local endpoint auditing and compliance monitoring only.
Run it only on systems you own or are explicitly permitted to monitor.

Workflow (mirrors the project spec):
    1. Monitor   - watchdog Observer reports create/modify/delete/move events
    2. Classify  - is the file inside a configured "sensitive" directory?
    3. Hash      - SHA-256 before (trusted baseline) and after (destination)
    4. Authorize - is the destination an approved path?
    5. Log/Alert - audit log + console; HIGH/CRITICAL for violations

Design notes
------------
* watchdog does NOT report "copy" events. A copy appears as a *created* file
  at the destination. We detect copies by matching the new file's SHA-256
  (or, for tampered copies, its file name) against the sensitive baseline.
* Moves across filesystems (e.g. to a USB stick) appear as create + delete,
  so deletes are correlated with recent transfers.
* Hashing runs in a worker thread so the watchdog observer is never blocked.
"""

import argparse
import fnmatch
import hashlib
import json
import logging
import os
import queue
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "sensitive_dirs": [],                 # directories whose files are protected
    "approved_destinations": [],          # where sensitive files MAY be moved/copied
    "watch_dirs": [],                     # extra dirs to watch (sensitive dirs are auto-watched)
    "removable_media_roots": ["/media", "/run/media", "/Volumes", "E:\\", "F:\\", "G:\\"],
    "network_share_roots": ["/mnt", "/net", "\\\\"],
    "download_dirs": [],                  # files appearing here are logged as DOWNLOAD
    "upload_staging_dirs": [],            # files appearing here are logged as UPLOAD (queued)
    "ignore_patterns": ["~$*", "*.swp", "*.swx", ".~lock.*#", ".DS_Store"],
    "log_file": "security_audit.log",
    "event_log_jsonl": "audit_events.jsonl",
    "baseline_file": "sensitive_baseline.json",
    "report_file": "security_report.txt",
    "log_all_events": True,               # also log non-sensitive file activity
    "sensitive_modification_severity": "HIGH",
    "move_correlation_seconds": 15,       # window to link create+delete into a MOVE
    "stability_interval_seconds": 0.5,    # poll interval to wait for copies to finish
}

SEVERITY_LEVEL = {"INFO": logging.INFO, "WARNING": logging.WARNING,
                  "HIGH": logging.ERROR, "CRITICAL": logging.CRITICAL}


def norm(path: str) -> str:
    """Canonical form used for every path comparison."""
    return os.path.normcase(os.path.realpath(os.path.expanduser(path)))


def is_under(path: str, roots: List[str]) -> bool:
    """True if `path` equals or lives beneath any directory in `roots`."""
    p = norm(path)
    for r in roots:
        base = r.rstrip(os.sep)
        if p == base or p.startswith(base + os.sep):
            return True
    return False


class Config:
    """Loads config.json, applies defaults, and normalises all paths."""

    def __init__(self, path: str):
        data = dict(DEFAULT_CONFIG)
        with open(path, "r", encoding="utf-8") as fh:
            data.update(json.load(fh))
        self.raw = data
        for key in ("sensitive_dirs", "approved_destinations", "watch_dirs",
                    "removable_media_roots", "network_share_roots",
                    "download_dirs", "upload_staging_dirs"):
            setattr(self, key, [norm(p) for p in data[key]])
        for key in ("ignore_patterns", "log_file", "event_log_jsonl", "baseline_file",
                    "report_file", "log_all_events", "sensitive_modification_severity",
                    "move_correlation_seconds", "stability_interval_seconds"):
            setattr(self, key, data[key])
        # The tool's own output files must never trigger events (feedback loop).
        self.own_files = {norm(data[k]) for k in ("log_file", "event_log_jsonl",
                                                  "baseline_file", "report_file")}


# --------------------------------------------------------------------------
# Hashing / integrity
# --------------------------------------------------------------------------
class HashEngine:
    """SHA-256 helper with retry (files may be briefly locked mid-copy)."""
    CHUNK = 1024 * 1024

    @staticmethod
    def sha256(path: str, retries: int = 4, delay: float = 0.5) -> Optional[str]:
        for _ in range(retries):
            try:
                digest = hashlib.sha256()
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(HashEngine.CHUNK), b""):
                        digest.update(chunk)
                return digest.hexdigest()
            except (PermissionError, OSError):
                time.sleep(delay)
        return None

    @staticmethod
    def wait_until_stable(path: str, interval: float = 0.5, timeout: float = 60) -> bool:
        """Block until size+mtime stop changing (copy finished). False if file vanished."""
        deadline, last = time.time() + timeout, None
        while time.time() < deadline:
            try:
                st = os.stat(path)
            except OSError:
                return False
            sig = (st.st_size, st.st_mtime_ns)
            if sig == last:
                return True
            last = sig
            time.sleep(interval)
        return True  # timed out - hash what we have


class BaselineStore:
    """Trusted path -> SHA-256 map of sensitive files, persisted to JSON so that
    tampering made while the monitor was offline is still detected."""

    def __init__(self, path: str):
        self.path, self._data, self._lock = path, {}, threading.RLock()

    def load(self) -> Dict[str, str]:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self._data = json.load(fh)
        return dict(self._data)

    def _save(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2)

    def get(self, p: str) -> Optional[str]:
        with self._lock:
            return self._data.get(norm(p))

    def set(self, p: str, h: str):
        with self._lock:
            self._data[norm(p)] = h
            self._save()

    def remove(self, p: str) -> Optional[str]:
        with self._lock:
            h = self._data.pop(norm(p), None)
            if h is not None:
                self._save()
            return h

    def find_by_hash(self, h: str) -> List[str]:
        with self._lock:
            return [p for p, v in self._data.items() if v == h]

    def find_by_name(self, name: str) -> List[str]:
        with self._lock:
            return [p for p in self._data if os.path.basename(p) == os.path.normcase(name)]

    def paths(self) -> List[str]:
        with self._lock:
            return list(self._data)


# --------------------------------------------------------------------------
# Audit logging
# --------------------------------------------------------------------------
class _ConsoleFormatter(logging.Formatter):
    def format(self, record):
        line = super().format(record)
        return (">>> ALERT " + line) if record.sev in ("HIGH", "CRITICAL") else line


class AuditLogger:
    """Writes a human-readable log (security_audit.log), console output,
    and a machine-readable JSONL stream used by the report generator."""

    def __init__(self, log_file: str, jsonl_file: str):
        self.jsonl_file, self._lock = jsonl_file, threading.Lock()
        self.log = logging.getLogger("dlp.audit")
        self.log.setLevel(logging.DEBUG)
        self.log.propagate = False
        self.log.handlers.clear()
        fmt = "%(asctime)s | %(sev)-8s | %(message)s"
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter(fmt, "%Y-%m-%d %H:%M:%S"))
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(_ConsoleFormatter(fmt, "%Y-%m-%d %H:%M:%S"))
        self.log.addHandler(fh)
        self.log.addHandler(ch)

    def record(self, event_type: str, severity: str, src: str = None,
               dst: str = None, **details):
        parts = [f"{event_type:<24}"]
        if src:
            parts.append(f"src={src}")
        if dst:
            parts.append(f"dst={dst}")
        parts += [f"{k}={v}" for k, v in details.items() if v is not None]
        self.log.log(SEVERITY_LEVEL[severity], " | ".join(parts), extra={"sev": severity})
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "severity": severity,
                 "event_type": event_type, "src": src, "dst": dst, **details}
        with self._lock, open(self.jsonl_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------
class PolicyEngine:
    """Answers: is it sensitive? is the destination approved? what kind of location?"""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def is_sensitive(self, path: str) -> bool:
        return is_under(path, self.cfg.sensitive_dirs)

    def is_approved(self, path: str) -> bool:
        # Staying inside the sensitive tree is always allowed.
        return is_under(path, self.cfg.approved_destinations) or self.is_sensitive(path)

    def location_type(self, path: str) -> str:
        if path.startswith("\\\\") or path.startswith("//") or is_under(path, self.cfg.network_share_roots):
            return "NETWORK_SHARE"
        if is_under(path, self.cfg.removable_media_roots):
            return "REMOVABLE_MEDIA"
        return "LOCAL_DISK"


# --------------------------------------------------------------------------
# watchdog glue: push raw events onto a queue, process them in a worker
# --------------------------------------------------------------------------
class _EventForwarder(FileSystemEventHandler):
    def __init__(self, q: "queue.Queue"):
        self.q = q

    def on_created(self, e):
        if not e.is_directory:
            self.q.put(("created", e.src_path, None))

    def on_modified(self, e):
        if not e.is_directory:
            self.q.put(("modified", e.src_path, None))

    def on_deleted(self, e):
        if not e.is_directory:
            self.q.put(("deleted", e.src_path, None))

    def on_moved(self, e):
        if not e.is_directory:
            self.q.put(("moved", e.src_path, e.dest_path))


@dataclass
class _Deletion:
    path: str
    sha: str
    ts: float


class DLPMonitor:
    """Ties everything together: observer -> queue -> classify/hash/authorize/alert."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.audit = AuditLogger(cfg.log_file, cfg.event_log_jsonl)
        self.policy = PolicyEngine(cfg)
        self.baseline = BaselineStore(cfg.baseline_file)
        self.hasher = HashEngine()
        self.q: "queue.Queue" = queue.Queue()
        self._stop = threading.Event()
        self._deletions: List[_Deletion] = []
        self._recent_copies: List[dict] = []       # for copy-then-delete => MOVE correlation
        self._reported = set()                      # (path, sha) dedupe: modified fires repeatedly
        self.observer = Observer()

    # ---- lifecycle -------------------------------------------------------
    def start(self):
        self._initial_scan()
        handler = _EventForwarder(self.q)
        for d in sorted(set(self.cfg.watch_dirs + self.cfg.sensitive_dirs)):
            if os.path.isdir(d):
                self.observer.schedule(handler, d, recursive=True)
                self.audit.record("WATCH_STARTED", "INFO", src=d)
            else:
                self.audit.record("WATCH_SKIPPED", "WARNING", src=d, note="directory does not exist")
        self.observer.start()
        threading.Thread(target=self._worker, daemon=True, name="dlp-worker").start()
        self.audit.record("MONITOR_STARTED", "INFO", note="press Ctrl+C to stop")

    def stop(self):
        self._stop.set()
        self.observer.stop()
        self.observer.join()
        self.audit.record("MONITOR_STOPPED", "INFO")

    def _worker(self):
        while not self._stop.is_set():
            try:
                kind, src, dst = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                if kind in ("created", "modified"):
                    self._handle_file_present(src)
                elif kind == "deleted":
                    self._handle_deleted(src)
                elif kind == "moved":
                    self._handle_moved(src, dst)
            except Exception as exc:  # never let one bad event kill the monitor
                self.audit.record("MONITOR_ERROR", "WARNING", src=src, note=repr(exc))

    # ---- helpers ---------------------------------------------------------
    def _ignored(self, path: str) -> bool:
        if norm(path) in self.cfg.own_files:
            return True
        name = os.path.basename(path)
        return any(fnmatch.fnmatch(name, pat) for pat in self.cfg.ignore_patterns)

    def _prune(self):
        cutoff = time.time() - self.cfg.move_correlation_seconds
        self._deletions = [d for d in self._deletions if d.ts >= cutoff]
        self._recent_copies = [c for c in self._recent_copies if c["ts"] >= cutoff]

    def _stable_hash(self, path: str) -> Optional[str]:
        if not self.hasher.wait_until_stable(path, self.cfg.stability_interval_seconds):
            return None
        return self.hasher.sha256(path)

    # ---- step 0: initial baseline / offline-tamper check ------------------
    def _initial_scan(self):
        previous = self.baseline.load()
        seen = set()
        for root in self.cfg.sensitive_dirs:
            for dirpath, _, files in os.walk(root):
                for name in files:
                    full = os.path.join(dirpath, name)
                    if self._ignored(full):
                        continue
                    h = self.hasher.sha256(full)
                    if h is None:
                        continue
                    key = norm(full)
                    seen.add(key)
                    old = previous.get(key)
                    if old is None:
                        self.audit.record("BASELINE_ADDED", "INFO", src=full, sha256=h)
                    elif old != h:
                        self.audit.record("INTEGRITY_FAILURE", "HIGH", src=full, sha256_before=old,
                                          sha256_after=h, note="modified while monitor was offline")
                    self.baseline.set(full, h)
        for missing in set(previous) - seen:
            self.audit.record("SENSITIVE_FILE_MISSING", "HIGH", src=missing,
                              sha256_before=previous[missing], note="existed in baseline, gone at startup")
            self.baseline.remove(missing)

    # ---- event handlers --------------------------------------------------
    def _handle_file_present(self, path: str):
        """created / modified: a file now exists at `path`."""
        if not os.path.isfile(path) or self._ignored(path):
            return
        if self.policy.is_sensitive(path):
            self._check_sensitive_file(path)
        else:
            self._analyze_outside_file(path)

    def _check_sensitive_file(self, path: str):
        post = self._stable_hash(path)
        if post is None:
            return
        known = self.baseline.get(path)
        if known is None:
            dupes = [p for p in self.baseline.find_by_hash(post) if p != norm(path)]
            self.audit.record("INTERNAL_COPY" if dupes else "NEW_SENSITIVE_FILE", "INFO",
                              src=dupes[0] if dupes else None, dst=path, sha256=post)
            self.baseline.set(path, post)
        elif known != post:
            self.audit.record("SENSITIVE_FILE_MODIFIED", self.cfg.sensitive_modification_severity,
                              src=path, sha256_before=known, sha256_after=post,
                              note="content changed - possible tampering")
            self.baseline.set(path, post)  # re-baseline so we alert once per change

    def _analyze_outside_file(self, path: str):
        """A file appeared/changed OUTSIDE the sensitive tree: is it a transfer?"""
        post = self._stable_hash(path)
        if post is None or (norm(path), post) in self._reported:
            return
        self._reported.add((norm(path), post))
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        origin = self._find_origin(path, post, size)
        if origin:
            src, pre, kind = origin
            self._evaluate_transfer(kind, src, path, pre, post)
            return
        # Not related to a sensitive file: ordinary activity
        if is_under(path, self.cfg.download_dirs):
            self.audit.record("DOWNLOAD", "INFO", dst=path, sha256=post)
        elif is_under(path, self.cfg.upload_staging_dirs):
            self.audit.record("UPLOAD_QUEUED", "INFO", dst=path, sha256=post)
        elif self.cfg.log_all_events:
            self.audit.record("FILE_ACTIVITY", "INFO", dst=path, sha256=post)

    def _find_origin(self, dst: str, post: str, size: int) -> Optional[Tuple[str, str, str]]:
        """Return (source_path, pre_hash, 'COPY'|'MOVE') if `dst` came from a sensitive file."""
        if size == 0:
            return None  # every empty file shares one hash - would false-match
        self._prune()
        # 1) identical content to a tracked sensitive file => copy
        for p in self.baseline.find_by_hash(post):
            if p != norm(dst):
                return p, post, "COPY"
        # 2) identical content to a sensitive file deleted moments ago => move
        for d in self._deletions:
            if d.sha == post:
                self._deletions.remove(d)
                return d.path, d.sha, "MOVE"
        # 3) SAME NAME, DIFFERENT CONTENT => corrupted / truncated / tampered transfer
        name = os.path.basename(dst)
        for p in self.baseline.find_by_name(name):
            return p, self.baseline.get(p), "COPY"
        for d in self._deletions:
            if os.path.basename(d.path) == os.path.normcase(name):
                self._deletions.remove(d)
                return d.path, d.sha, "MOVE"
        return None

    def _evaluate_transfer(self, kind: str, src: str, dst: str, pre: str, post: str):
        """Steps 3-5: compare hashes, check authorization, log/alert."""
        approved = self.policy.is_approved(dst)
        dest_type = self.policy.location_type(dst)
        if pre != post:
            self.audit.record("INTEGRITY_FAILURE", "CRITICAL", src=src, dst=dst,
                              sha256_before=pre, sha256_after=post,
                              note="hash mismatch after transfer - corrupted, truncated or tampered")
        if approved:
            self.audit.record(f"AUTHORIZED_{kind}", "INFO", src=src, dst=dst, sha256_before=pre,
                              sha256_after=post, integrity="PASS" if pre == post else "FAIL")
        else:
            self.audit.record(f"UNAUTHORIZED_{kind}", "CRITICAL", src=src, dst=dst,
                              dest_type=dest_type, sha256_before=pre, sha256_after=post,
                              integrity="PASS" if pre == post else "FAIL",
                              policy="sensitive file sent to a destination not in approved_destinations")
        if kind == "COPY":
            self._recent_copies.append({"src": norm(src), "dst": dst, "approved": approved,
                                        "ts": time.time()})

    def _handle_deleted(self, path: str):
        sha = self.baseline.remove(path)
        if sha is None:
            return  # not a tracked sensitive file
        self._prune()
        self._deletions.append(_Deletion(norm(path), sha, time.time()))
        # copy followed by delete of the original == a move across filesystems
        matches = [c for c in self._recent_copies if c["src"] == norm(path)]
        if matches:
            c = max(matches, key=lambda x: x["ts"])  # the most recent copy is the move target
            self.audit.record("MOVE_CORRELATED", "INFO" if c["approved"] else "CRITICAL",
                              src=path, dst=c["dst"], sha256_before=sha,
                              note="copy followed by deletion of original = MOVE")
            return
        self.audit.record("SENSITIVE_FILE_DELETED", "HIGH", src=path, sha256_before=sha,
                          note="tracked sensitive file removed")

    def _handle_moved(self, src: str, dst: str):
        pre = self.baseline.get(src)
        if pre is None:
            # Untracked source (e.g. temp->final rename): treat dst like a new file.
            self._handle_file_present(dst)
            return
        self.baseline.remove(src)
        post = self._stable_hash(dst)
        if post is None:
            return
        self._reported.add((norm(dst), post))
        if self.policy.is_sensitive(dst):
            self.audit.record("INTERNAL_MOVE", "INFO", src=src, dst=dst, sha256_before=pre, sha256_after=post)
            if pre != post:
                self.audit.record("INTEGRITY_FAILURE", "HIGH", src=src, dst=dst,
                                  sha256_before=pre, sha256_after=post, note="content changed during move")
            self.baseline.set(dst, post)
        else:
            self._evaluate_transfer("MOVE", src, dst, pre, post)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
class ReportGenerator:
    """Builds a human-readable summary from audit_events.jsonl."""

    @staticmethod
    def generate(jsonl_file: str, out_file: str) -> str:
        if not os.path.exists(jsonl_file):
            return "No audit events recorded yet."
        events = [json.loads(l) for l in open(jsonl_file, encoding="utf-8") if l.strip()]
        sev = Counter(e["severity"] for e in events)
        types = Counter(e["event_type"] for e in events)
        alerts = [e for e in events if e["severity"] in ("HIGH", "CRITICAL")]
        lines = ["=" * 78, "DLP SECURITY AUDIT REPORT", "=" * 78,
                 f"Generated : {datetime.now(timezone.utc).isoformat()}",
                 f"Period    : {events[0]['timestamp']}  ->  {events[-1]['timestamp']}",
                 f"Events    : {len(events)}", "", "Events by severity:"]
        lines += [f"  {s:<9}{sev.get(s, 0)}" for s in ("CRITICAL", "HIGH", "WARNING", "INFO")]
        lines += ["", "Events by type:"] + [f"  {t:<26}{n}" for t, n in types.most_common()]
        lines += ["", f"High-severity alerts ({len(alerts)}):", "-" * 78]
        for e in alerts:
            lines.append(f"[{e['timestamp']}] {e['severity']} {e['event_type']}")
            for k in ("src", "dst", "dest_type", "sha256_before", "sha256_after", "note", "policy"):
                if e.get(k):
                    lines.append(f"    {k:<14}: {e[k]}")
        if not alerts:
            lines.append("  none - no policy violations recorded")
        text = "\n".join(lines) + "\n"
        with open(out_file, "w", encoding="utf-8") as fh:
            fh.write(text)
        return text


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Defensive DLP / secure file transfer monitor")
    ap.add_argument("-c", "--config", default="config.json", help="path to config.json")
    ap.add_argument("--report", action="store_true", help="generate report from existing logs and exit")
    ap.add_argument("--rebuild-baseline", action="store_true",
                    help="discard stored hashes and trust the current state of sensitive dirs")
    args = ap.parse_args()

    cfg = Config(args.config)
    if args.report:
        print(ReportGenerator.generate(cfg.event_log_jsonl, cfg.report_file))
        return
    if args.rebuild_baseline and os.path.exists(cfg.baseline_file):
        os.remove(cfg.baseline_file)

    monitor = DLPMonitor(cfg)
    monitor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print(ReportGenerator.generate(cfg.event_log_jsonl, cfg.report_file))


if __name__ == "__main__":
    main()
