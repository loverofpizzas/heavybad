#!/usr/bin/env python3
"""
heavybad.py v1.0.6 — Multi-pass bad-sector detector for Linux raw block devices
https://github.com/loverofpizzas/heavybad

Changelog
─────────
v1.0.6
  Progress bar:
    - Shortened field labels (B: / Sl: / Sk:) and M/K suffixes on large numbers
      to keep the line from wrapping on normal terminal widths.
    - Speed (MB/s) now reflects actual disk I/O only: skipped LBAs are excluded
      from the throughput calculation. ETA still uses wall-clock time per chunk
      (which includes skipping) so it remains accurate.
  Streaming mode:
    - skip_lbas resets to 0 at the start of each write or verify phase.
      bad_lbas and slow_lbas are cumulative and are preserved across phases.
    - Live skip list update: after every write phase, newly flagged bad and slow
      sectors are flushed into the in-memory IntervalSet so the following verify
      phase (and all subsequent passes) skip them automatically. Same flush
      happens after every verify phase for the next pass's write phase.

v1.0.5
  New: --streaming mode (destructive only)
    - Writes the entire scan range with one pattern, issues a single fdatasync,
      then reads the entire range back for verification — matching the I/O model
      used by badblocks -w and h2testw.  The key difference from chunk mode is
      that writes are not sync-flushed after each chunk; instead the OS and drive
      firmware are free to pipeline writes into one sustained sequential burst.
      This creates the sustained platter write pressure that reveals marginal
      sectors which pass per-chunk O_SYNC writes but fail under real workloads.
    - ~3× faster than chunk mode at equivalent pass count because the O_SYNC
      barrier overhead is eliminated and verify-reads is implicitly 1 per chunk.
    - RAND pattern: a single os.urandom() tile (chunk_bytes) is generated once
      per pass and reused for every chunk, eliminating the need to regenerate
      matching random data during the verify phase.
    - Write errors during the write phase are recorded immediately (as in chunk
      mode); the affected chunk is skipped in the verify phase.
    - --retries applies to verify-phase reads.  --verify-reads is not used.
    - Resume: pass-level granularity.  If interrupted, the current pattern pass
      restarts from scratch on next run.  A new RAND tile is generated for that
      pass.  Pass-level state is stored in the resume file as stream_pass_idx.

v1.0.4
  Bug Fixes
    - With --rand-passes > 1, every RAND pass was reported identically as
      "RAND" in BAD/SLOW events and logs, so a failure couldn't be attributed
      to a specific RAND pass. Each RAND pass is now individually labeled
      "RAND i/N" (e.g. "OSError RAND 3/4: ..."), and the config header's
      "Passes" line shows each one explicitly.

v1.0.3
  Bug Fixes
    - Queue resume could silently apply to the wrong scan: the resume file was
      matched only on device/start_lba/end_lba, but a queue's read pass
      (chunk_size=1) and destructive pass (chunk_size=4096) typically share the
      same range. A resume file saved mid-destructive-pass would be loaded by
      the read pass on restart, "resuming" at a chunk offset that — at
      chunk_size=1 — corresponds to a position essentially at the start of the
      range, while printing a normal-looking "Resuming from..." message. The
      read pass would then also clear the resume file on completion, losing the
      destructive pass's progress entirely.
      Fixed by also storing chunk_size/destructive in the resume file and
      requiring all four (device, range, chunk_size, mode) to match before a
      scan resumes from it. If a resume file belongs to a different scan step,
      it's left untouched. In queue mode, the matching scan step is detected at
      startup and earlier (already-completed) scans are skipped on the first loop.

  New: --rand-passes N
    - Repeats the RAND write pattern N times in a row at the end of each
      destructive pass (only applies if --passes 5, i.e. RAND is included).
      RAND is the most effective single pattern at catching marginal sectors
      that the deterministic 0xAA/0x55/0xFF/0x00 patterns miss; stacking extra
      RAND passes concentrates additional stress there without affecting the
      deterministic passes or their per-pattern failure diagnostics.
    - Supported in queue.json at both top level and per-scan (per-scan takes
      precedence).
    - Config header's "Passes" line now shows the full pattern sequence with
      repeated patterns collapsed, e.g. "0xAA, 0x55, 0xFF, 0x00, RAND ×4".

v1.0.2
  Bug Fixes
    - Progress bar exceeded 100%: Progress.tick() incremented done on every
      sub-range call rather than once per chunk. A chunk with partial skip
      overlap generated multiple tick() calls, causing done to overshoot total.
      Fixed by separating stat accumulation (tick) from chunk counting (advance),
      with advance() called exactly once per chunk.
    - Slow sector response time always reported as ~8ms in destructive mode:
      read_ms was overwritten on every verify read across every pattern pass, so
      by the time the slow event was recorded it held the last read's time (often
      fast). Fixed by tracking peak_read_ms across all reads per sub-range.

  New: Logging (--log FILE)
    - --log FILE writes a timestamped log in append mode. Successive scans and
      queue runs accumulate in the same file without overwriting.
    - Logs a config header at scan start, every BAD event with LBA range and
      error reason, every SLOW event with LBA range and peak response time, and
      a full summary block at the end (chunks scanned, LBAs skipped, bad/slow
      counts, total flagged, scan status).
    - Supported in queue.json at both top level and per-scan (per-scan takes
      precedence), consistent with how resume behaves.

v1.0.1
  Bug Fixes
    - AttributeError on queue mode startup: 'Namespace' object has no attribute
      'merge_skip' — attribute was missing from the queue-built Namespace.
    - 'Merge skip' config line incorrectly showed 'no' in queue mode even when
      auto-merging was active.
    - 'Resume' config line incorrectly showed 'disabled' when resume was set at
      the top level of queue.json rather than per-scan.
    - Removed stale 'LED indicators' label from Progress section header.

  New: Unified List
    - If --output and --skip-list point to the same file, heavybad enters unified
      list mode. Newly flagged sectors are appended directly onto the skip list,
      combining both roles into a single file. No separate merge step is needed
      or performed. The config header labels the file as [unified list].
    - In queue mode, unified list is detected per-scan and the post-scan
      merge_into_skip_list call is skipped automatically.
    - In CLI mode, passing --merge-skip alongside a unified list emits a warning
      and is ignored.
"""

import os
import sys
import time
import ctypes
import argparse
import bisect
import signal
import json
import subprocess
import datetime
from pathlib import Path

VERSION = "1.0.6"


# ─────────────────────────────────────────────────────────────────────────────
#  Write patterns
# ─────────────────────────────────────────────────────────────────────────────

WRITE_PATTERNS = [
    (b'\xAA', "0xAA"),
    (b'\x55', "0x55"),
    (b'\xFF', "0xFF"),
    (b'\x00', "0x00"),
    (None,    "RAND"),
]

def build_pattern_sequence(passes: int, rand_passes: int = 1):
    """
    Build the ordered list of (pattern_bytes_or_None, name) write patterns
    for a destructive scan.

    `passes` selects the first N entries of WRITE_PATTERNS (1-5). If RAND
    (the 5th/final pattern) is included and `rand_passes` > 1, the single
    RAND entry is replaced with `rand_passes` entries labeled "RAND i/N" —
    each gets fresh random data and a distinct name, so a failure on any
    individual RAND pass is identifiable (e.g. "OSError RAND 3/4: ...")
    rather than every RAND pass being reported identically as "RAND".
    """
    base = list(WRITE_PATTERNS[:passes])
    if base and base[-1][1] == "RAND" and rand_passes > 1:
        rand_pat = base[-1][0]  # None — generates fresh os.urandom() per pass
        base = base[:-1] + [(rand_pat, f"RAND {i+1}/{rand_passes}") for i in range(rand_passes)]
    return base

def format_pattern_sequence(patterns) -> str:
    """Collapse consecutive repeated pattern names for display, e.g.
    [0xAA, 0x55, 0xFF, 0x00, RAND, RAND, RAND] -> '0xAA, 0x55, 0xFF, 0x00, RAND ×3'"""
    if not patterns:
        return ""
    parts = []
    i = 0
    while i < len(patterns):
        name = patterns[i][1]
        count = 1
        while i + count < len(patterns) and patterns[i + count][1] == name:
            count += 1
        parts.append(name if count == 1 else f"{name} ×{count}")
        i += count
    return ", ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
#  libc / kernel bindings
# ─────────────────────────────────────────────────────────────────────────────

_libc = ctypes.CDLL("libc.so.6", use_errno=True)

_ioctl              = _libc.ioctl
_ioctl.restype      = ctypes.c_int

_memalign           = _libc.posix_memalign
_memalign.restype   = ctypes.c_int
_memalign.argtypes  = [ctypes.POINTER(ctypes.c_void_p),
                       ctypes.c_size_t, ctypes.c_size_t]

_free               = _libc.free
_free.restype       = None
_free.argtypes      = [ctypes.c_void_p]

_cread              = _libc.read
_cread.restype      = ctypes.c_ssize_t
_cread.argtypes     = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]

_cwrite             = _libc.write
_cwrite.restype     = ctypes.c_ssize_t
_cwrite.argtypes    = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]

_fdatasync          = _libc.fdatasync
_fdatasync.restype  = ctypes.c_int
_fdatasync.argtypes = [ctypes.c_int]

BLKGETSIZE64 = 0x80081272
O_DIRECT     = 0x4000


# ─────────────────────────────────────────────────────────────────────────────
#  Aligned buffer
# ─────────────────────────────────────────────────────────────────────────────

class AlignedBuf:
    def __init__(self, size: int, alignment: int = 4096):
        self.size      = size
        self.alignment = alignment
        self._ptr      = ctypes.c_void_p(0)
        ret = _memalign(ctypes.byref(self._ptr), alignment, size)
        if ret != 0:
            raise MemoryError(f"posix_memalign({alignment}, {size}) → errno {ret}")
        self._arr = (ctypes.c_char * size).from_address(self._ptr.value)

    @property
    def addr(self) -> int:
        return self._ptr.value

    def read_into(self, fd: int) -> bytes:
        n = _cread(fd, ctypes.c_void_p(self._ptr.value), ctypes.c_size_t(self.size))
        if n < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
        if n != self.size:
            raise OSError(0, f"Short read: {n}/{self.size} bytes")
        return bytes(self._arr)

    def write_from(self, fd: int, data: bytes) -> int:
        ctypes.memmove(self._ptr.value, data, len(data))
        n = _cwrite(fd, ctypes.c_void_p(self._ptr.value), ctypes.c_size_t(len(data)))
        if n < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
        return n

    def __del__(self):
        if self._ptr.value:
            _free(self._ptr)
            self._ptr.value = 0


# ─────────────────────────────────────────────────────────────────────────────
#  Device helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_device_bytes(fd: int) -> int:
    buf = ctypes.c_uint64(0)
    ret = _ioctl(fd, BLKGETSIZE64, ctypes.byref(buf))
    if ret != 0:
        raise OSError(ctypes.get_errno(), "ioctl BLKGETSIZE64 failed")
    return int(buf.value)


# ─────────────────────────────────────────────────────────────────────────────
#  Temperature poller — reads drive temp via smartctl every 30 seconds
# ─────────────────────────────────────────────────────────────────────────────

class TempPoller:
    INTERVAL = 30  # seconds between smartctl calls

    def __init__(self, device: str):
        self._device  = device
        self._temp    = None   # int °C or None if unavailable
        self._last    = 0.0

    def get(self) -> str:
        """Return temperature string like '54°C', or '' if unavailable."""
        now = time.monotonic()
        if now - self._last >= self.INTERVAL:
            self._last = now
            self._poll()
        if self._temp is None:
            return ''
        return f"{self._temp}\xb0C"

    def _poll(self):
        try:
            out = subprocess.check_output(
                ["smartctl", "-A", self._device],
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).decode(errors='replace')
            for line in out.splitlines():
                parts = line.split()
                # SMART attribute 190 (Airflow_Temperature) or 194 (Temperature_Celsius)
                if len(parts) >= 10 and parts[0] in ('190', '194'):
                    self._temp = int(parts[9])
                    return
            self._temp = None
        except Exception:
            self._temp = None



class IntervalSet:
    def __init__(self):
        self._raw:    list[tuple[int,int]] = []
        self._merged: list[tuple[int,int]] = []
        self._starts: list[int] = []
        self._built   = False

    def add(self, lba: int):
        self._raw.append((lba, lba)); self._built = False

    def add_range(self, start: int, end: int):
        if end < start: start, end = end, start
        self._raw.append((start, end)); self._built = False

    def build(self):
        if self._built: return
        merged: list[list[int]] = []
        for s, e in sorted(self._raw):
            if merged and s <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        self._merged = [(s, e) for s, e in merged]
        self._starts = [s for s, _ in self._merged]
        self._built  = True

    def __contains__(self, lba: int) -> bool:
        if not self._built: self.build()
        idx = bisect.bisect_right(self._starts, lba) - 1
        if idx >= 0:
            s, e = self._merged[idx]
            return s <= lba <= e
        return False

    def count(self) -> int:
        if not self._built: self.build()
        return sum(e - s + 1 for s, e in self._merged)

    def range_count(self) -> int:
        if not self._built: self.build()
        return len(self._merged)


# ─────────────────────────────────────────────────────────────────────────────
#  Skip-list loader
# ─────────────────────────────────────────────────────────────────────────────

def load_skip_list(path: str | None) -> IntervalSet:
    iv = IntervalSet()
    if not path:
        iv.build(); return iv
    p = Path(path)
    if not p.exists():
        print(f"[!] Skip list not found: {path}", file=sys.stderr); sys.exit(1)
    with open(p) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith('#'): continue
            try:
                if '-' in line:
                    a, b = line.split('-', 1)
                    iv.add_range(int(a.strip()), int(b.strip()))
                elif ' ' in line or '\t' in line:
                    parts = line.split()
                    if len(parts) == 2:
                        iv.add_range(int(parts[0]), int(parts[1]))
                    else: raise ValueError
                else:
                    iv.add(int(line))
            except ValueError:
                print(f"  [!] Skip list line {lineno}: cannot parse '{line}' — skipped")
    iv.build()
    print(f"[+] Skip list : {iv.count():>12,} LBAs  ({iv.range_count():,} ranges)")
    return iv


# ─────────────────────────────────────────────────────────────────────────────
#  Resume file
# ─────────────────────────────────────────────────────────────────────────────

RESUME_FILE = Path(__file__).resolve().parent / "heavybad.resume"

def load_resume() -> dict | None:
    if RESUME_FILE.exists():
        try:
            with open(RESUME_FILE) as f:
                return json.load(f)
        except Exception:
            return None
    return None

def _resume_match(state: dict | None, device, start_lba, end_lba, chunk_size, destructive, streaming: bool = False) -> str:
    """
    Compare a loaded resume state against the scan about to run.

    Returns:
      'scan'  — state matches this exact scan (range AND chunk_size/mode/streaming) — safe to resume
      'range' — same device/range but a different scan step (e.g. the other
                pass in a queue) — leave the file alone, it belongs to that scan
      'none'  — unrelated/stale — safe to discard
    """
    if not state:
        return 'none'
    same_range = (state.get('device')    == device    and
                   state.get('start_lba') == start_lba and
                   state.get('end_lba')   == end_lba)
    if not same_range:
        return 'none'
    same_scan = (state.get('chunk_size')  == chunk_size and
                  state.get('destructive') == destructive and
                  state.get('streaming', False) == streaming)
    return 'scan' if same_scan else 'range'

def save_resume(data: dict):
    try:
        with open(RESUME_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        print(f"\n[!] Could not save resume file: {e}", file=sys.stderr)

def clear_resume():
    try:
        RESUME_FILE.unlink(missing_ok=True)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  Skip-list merger — appends new findings to existing skip list (raw append)
# ─────────────────────────────────────────────────────────────────────────────

def merge_into_skip_list(skip_path: str, *output_paths: str):
    """Append contents of output_paths to skip_path. Raw append, no sorting."""
    if not skip_path:
        return
    appended = 0
    with open(skip_path, 'a') as dst:
        for path in output_paths:
            if not path or not Path(path).exists():
                continue
            with open(path) as src:
                for line in src:
                    dst.write(line)
                    appended += 1
    if appended:
        print(f"[+] Merged {appended:,} lines into skip list: {skip_path}")


# ─────────────────────────────────────────────────────────────────────────────
#  Queue runner — runs multiple scans from a JSON config file
# ─────────────────────────────────────────────────────────────────────────────

def run_queue(queue_file: str):
    """
    Run a sequence of scans defined in a JSON file.

    queue.json format:
    {
        "device":    "/dev/sda",
        "skip_list": "/path/to/skip.txt",
        "repeat":    true,          // or integer N for N full loops
        "scans": [
            {
                "mode":         "read",        // "read" or "destructive"
                "chunk_size":   1,
                "slow_ms":      150,
                "start_lba":    2048,
                "end_lba":      346791935,
                "passes":       5,             // destructive only
                "rand_passes":  4,             // destructive only, requires passes:5
                "verify_reads": 3,             // destructive only
                "retries":      0,
                "output":       "/path/to/out.txt",
                "slow_output":  "/path/to/slow.txt",  // optional
                "histogram":    true,
                "verbose":      false
            }
        ]
    }
    After each scan, its output is automatically appended to the skip list.

    streaming is supported as a top-level default and per-scan override:
        "streaming": true
    """
    p = Path(queue_file)
    if not p.exists():
        print(f"[!] Queue file not found: {queue_file}", file=sys.stderr); sys.exit(1)

    import argparse as _ap

    with open(p) as f:
        cfg = json.load(f)

    device    = cfg.get('device')
    skip_path = cfg.get('skip_list', '')
    repeat    = cfg.get('repeat', 1)
    scans     = cfg.get('scans', [])

    if not device:
        print("[!] Queue file missing 'device' key.", file=sys.stderr); sys.exit(1)
    if not scans:
        print("[!] Queue file has no scans defined.", file=sys.stderr); sys.exit(1)

    # If any scan is destructive, confirm once upfront
    has_destructive = any(s.get('mode') == 'destructive' for s in scans)
    if has_destructive:
        print("=" * 64)
        print("  WARNING: DESTRUCTIVE MODE")
        print("  One or more scans in this queue will permanently overwrite")
        print("  data in the scanned range.")
        print("  Only use this on unallocated/expendable regions.")
        print("=" * 64)
        if input("  Type YES to proceed with entire queue: ").strip() != "YES":
            print("Aborted."); sys.exit(0)
        print()

    # repeat=True means endless, repeat=N means N loops
    endless    = (repeat is True)
    loop_limit = None if endless else int(repeat)
    loop       = 0

    # If a resume file exists and matches one of this queue's scans (by
    # device/range/chunk_size/mode), skip the scans before it on the first
    # loop — they already ran to completion in the prior (interrupted) run.
    resume_skip_to = 0
    any_resume = cfg.get('resume', False) or any(s.get('resume', False) for s in scans)
    if any_resume:
        _state = load_resume()
        if _state:
            for i, sc in enumerate(scans):
                sc_chunk = sc.get('chunk_size', 8)
                sc_destr = (sc.get('mode', 'read') == 'destructive')
                sc_start = sc.get('start_lba', 0)
                sc_end   = sc.get('end_lba', None)
                if _resume_match(_state, device, sc_start, sc_end,
                                  sc_chunk, sc_destr) == 'scan':
                    resume_skip_to = i
                    print(f"[+] Resume file matches scan {i+1}/{len(scans)} — "
                          f"skipping earlier scans in this run (assumed already complete).")
                    print()
                    break

    print(f"[+] Queue loaded: {len(scans)} scan(s), "
          f"repeat={'endless' if endless else loop_limit}, "
          f"device={device}")
    print()

    while True:
        loop += 1
        if not endless and loop > loop_limit:
            break

        if endless or loop_limit > 1:
            print(f"{'='*64}")
            print(f"  LOOP {loop}" + ('' if endless else f" / {loop_limit}"))
            print(f"{'='*64}")
            print()

        for scan_idx, scan_cfg in enumerate(scans):
            if loop == 1 and scan_idx < resume_skip_to:
                print(f"[+] Scan {scan_idx+1}/{len(scans)} (loop {loop}) — "
                      f"skipped (already completed before interruption)")
                print()
                continue

            print(f"[+] Scan {scan_idx+1}/{len(scans)} (loop {loop})")

            # Pre-compute unified list mode (output == skip list → same file)
            _output  = scan_cfg.get('output', None)
            _unified = bool(_output and skip_path and
                            Path(str(_output)).resolve() == Path(str(skip_path)).resolve())

            # Build a Namespace mimicking argparse args
            args = _ap.Namespace(
                device        = device,
                destructive   = (scan_cfg.get('mode', 'read') == 'destructive'),
                start_lba     = scan_cfg.get('start_lba', 0),
                end_lba       = scan_cfg.get('end_lba', None),
                sector_size   = scan_cfg.get('sector_size', 512),
                chunk_size    = scan_cfg.get('chunk_size', 8),
                passes        = scan_cfg.get('passes', 4),
                rand_passes   = scan_cfg.get('rand_passes', cfg.get('rand_passes', 1)),
                verify_reads  = scan_cfg.get('verify_reads', 3),
                retries       = scan_cfg.get('retries', 0),
                slow_ms       = scan_cfg.get('slow_ms', 200),
                skip_list     = skip_path or None,
                output        = _output,
                slow_output   = scan_cfg.get('slow_output', None),
                log           = scan_cfg.get('log', cfg.get('log', None)),
                resume        = scan_cfg.get('resume', cfg.get('resume', False)),
                histogram     = scan_cfg.get('histogram', False),
                dry_run       = False,
                verbose       = scan_cfg.get('verbose', False),
                fs            = scan_cfg.get('fs', cfg.get('fs', None)),
                skip_confirmation = True,   # already confirmed at queue startup
                streaming     = scan_cfg.get('streaming', cfg.get('streaming', False)),
                merge_skip    = bool(skip_path and _output and not _unified),
            )

            skip = load_skip_list(args.skip_list)
            print()
            scan(args, skip)

            # Merge this scan's output into the skip list (skipped in unified list mode)
            if skip_path and args.output and not _unified:
                merge_into_skip_list(skip_path, args.output, args.slow_output or '')
                print()

        if not endless and loop >= loop_limit:
            break

    print("[+] Queue complete.")



HIST_BUCKETS = [
    ("  0– 50ms",  50),
    (" 50–200ms", 200),
    ("200–500ms", 500),
    ("   500ms+", None),
]

class Histogram:
    def __init__(self):
        self.counts = [0] * len(HIST_BUCKETS)

    def record(self, ms: float):
        for i, (_, limit) in enumerate(HIST_BUCKETS):
            if limit is None or ms < limit:
                self.counts[i] += 1
                return

    def print(self, total_reads: int):
        print("\n  Response time histogram:")
        bar_w = 30
        for i, (label, _) in enumerate(HIST_BUCKETS):
            c   = self.counts[i]
            pct = c / total_reads * 100 if total_reads else 0
            bar = '█' * int(bar_w * pct / 100)
            print(f"    {label}  {bar:<{bar_w}}  {pct:5.1f}%  ({c:,})")


# ─────────────────────────────────────────────────────────────────────────────
#  Output writer — supports NTFS (range) and ext (flat block numbers) formats
# ─────────────────────────────────────────────────────────────────────────────

class OutputWriter:
    """
    NTFS mode: writes 'start end' ranges in real time (consecutive LBAs
               extend the open range silently, flushed on gap or close).
    ext mode:  writes flat 4096-byte block numbers (LBA // 8), deduplicated,
               one per line — ready for e2fsck -l.
    """
    def __init__(self, path: str, fs: str):
        self._f      = open(path, 'a')
        self._fs     = fs          # 'ntfs' or 'ext'
        # ntfs state
        self._start  = None
        self._end    = None
        # ext state — track last written block to deduplicate
        self._last_block = -1

    def write_range(self, lba_s: int, lba_e: int):
        if self._fs == 'ntfs':
            self._write_ntfs(lba_s, lba_e)
        else:
            self._write_ext(lba_s, lba_e)

    # ── NTFS ──────────────────────────────────────────────────────────────────
    def _write_ntfs(self, lba_s: int, lba_e: int):
        if self._start is None:
            self._start = lba_s
            self._end   = lba_e
        elif lba_s == self._end + 1:
            self._end = lba_e
        else:
            self._flush_ntfs()
            self._start = lba_s
            self._end   = lba_e

    def _flush_ntfs(self):
        if self._start is not None:
            self._f.write(f"{self._start} {self._end}\n")
            self._f.flush()

    # ── ext ───────────────────────────────────────────────────────────────────
    def _write_ext(self, lba_s: int, lba_e: int):
        block_s = lba_s // 8
        block_e = lba_e // 8
        for block in range(block_s, block_e + 1):
            if block != self._last_block:
                self._f.write(f"{block}\n")
                self._last_block = block
        self._f.flush()

    # ── shared ────────────────────────────────────────────────────────────────
    def close(self):
        if self._fs == 'ntfs':
            self._flush_ntfs()
        self._start = self._end = None
        self._f.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Sub-range splitter — scans only non-skipped LBAs within a chunk
# ─────────────────────────────────────────────────────────────────────────────

def get_scan_subranges(lba_s: int, lba_e: int, skip: IntervalSet) -> list[tuple[int,int]]:
    """
    Split [lba_s, lba_e] into sub-ranges that are NOT in the skip list.
    Only bad LBAs are skipped — the rest of the chunk is scanned normally.
    """
    ranges    = []
    cur_start = None
    for lba in range(lba_s, lba_e + 1):
        if lba in skip:
            if cur_start is not None:
                ranges.append((cur_start, lba - 1))
                cur_start = None
        else:
            if cur_start is None:
                cur_start = lba
    if cur_start is not None:
        ranges.append((cur_start, lba_e))
    return ranges


# ─────────────────────────────────────────────────────────────────────────────
#  Logger
# ─────────────────────────────────────────────────────────────────────────────

class Logger:
    """
    Timestamped log writer.  Opens in append mode so successive scans (e.g.
    in queue mode) accumulate in the same file without overwriting each other.
    Every write is flushed immediately so the log is always current on disk.
    """
    def __init__(self, path: str):
        self._f = open(path, 'a', encoding='utf-8')

    def _ts(self) -> str:
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def write(self, msg: str = ''):
        self._f.write(f"[{self._ts()}] {msg}\n")
        self._f.flush()

    def close(self):
        self._f.close()



def _fmt_eta(seconds: float) -> str:
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d > 0:
        return f"{d}d {h:02d}:{m:02d}:{s:02d}"
    return f"{h:02d}:{m:02d}:{s:02d}"


def _fmt_lbas(n: int) -> str:
    """Compact LBA count for progress display: 1,234,567 → 1.2M."""
    if n >= 1_000_000: return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:     return f"{n / 1_000:.1f}K"
    return str(n)


class Progress:
    def __init__(self, total_chunks: int, chunk_lbas: int, chunk_bytes: int,
                 resume_bad: int = 0, resume_slow: int = 0,
                 temp_poller: 'TempPoller | None' = None,
                 label: str = ''):
        self.total        = total_chunks
        self.chunk_lbas   = chunk_lbas
        self.chunk_bytes  = chunk_bytes
        self.done         = 0
        self.bad_lbas     = resume_bad
        self.bad_chunks   = 0
        self.slow_lbas    = resume_slow
        self.slow_chunks  = 0
        self.skip_lbas    = 0
        self.total_reads  = 0
        self.t0           = time.monotonic()
        self._last        = 0.0
        self._temp        = temp_poller
        self._label       = label

    def set_label(self, label: str):
        """Update the phase label shown in the progress bar (streaming mode)."""
        self._label = label
        self._last  = 0.0   # force immediate redraw

    def reset(self, total_chunks: int):
        """Reset for the next write/verify phase (streaming mode).
        skip_lbas resets to 0 (per-phase counter).
        bad_lbas/slow_lbas are preserved (cumulative scan results)."""
        self.total      = total_chunks
        self.done       = 0
        self.skip_lbas  = 0
        self.t0         = time.monotonic()
        self._last      = 0.0

    def tick(self, bad: int = 0, slow: int = 0, skipped: int = 0):
        if bad:
            self.bad_lbas   += bad
            self.bad_chunks += 1
        if slow:
            self.slow_lbas   += slow
            self.slow_chunks += 1
        if skipped:
            self.skip_lbas += skipped
        now = time.monotonic()
        if now - self._last < 0.3: return
        self._last = now
        self._draw()

    def advance(self):
        """Advance the chunk counter by exactly 1. Call once per chunk."""
        self.done += 1
        now = time.monotonic()
        if now - self._last < 0.3: return
        self._last = now
        self._draw()

    def _draw(self):
        pct     = self.done / self.total * 100 if self.total else 0
        elapsed = time.monotonic() - self.t0 or 1e-9
        temp    = f"  {self._temp.get()}" if self._temp else ""
        label   = f"[{self._label}] " if self._label else ""

        # ETA: wall-clock rate (includes skipping — gives accurate finish time)
        wall_rate = self.done * self.chunk_bytes / elapsed
        eta_s     = (self.total - self.done) * self.chunk_bytes / wall_rate if wall_rate > 0 else 0
        eta       = _fmt_eta(eta_s)

        # MB/s: actual disk I/O only (skipped LBAs excluded)
        sector_sz = self.chunk_bytes // self.chunk_lbas if self.chunk_lbas else 512
        io_lbas   = max(0, self.done * self.chunk_lbas - self.skip_lbas)
        rate_mb   = io_lbas * sector_sz / elapsed / (1 << 20)

        W = 20; f = int(W * pct / 100)
        bar = '█' * f + '░' * (W - f)

        sys.stdout.write(
            f"\r{label}[{bar}] {pct:5.1f}%  "
            f"chunk {self.done:,}/{self.total:,}  "
            f"B:{_fmt_lbas(self.bad_lbas)}({self.bad_chunks})  "
            f"Sl:{_fmt_lbas(self.slow_lbas)}({self.slow_chunks})  "
            f"Sk:{_fmt_lbas(self.skip_lbas)}  "
            f"{rate_mb:5.1f} MB/s  ETA {eta}{temp}  "
        )
        sys.stdout.flush()

    def finish(self):
        self._draw(); print()


# ─────────────────────────────────────────────────────────────────────────────
#  Core scan
# ─────────────────────────────────────────────────────────────────────────────

def scan(args, skip: IntervalSet):
    sector_size = args.sector_size
    chunk_lbas  = args.chunk_size
    chunk_bytes = chunk_lbas * sector_size

    # ── resolve filesystem type ───────────────────────────────────────────────
    fs = getattr(args, 'fs', None)
    if not fs and not args.dry_run:
        while True:
            fs = input("  Filesystem type? [ntfs/ext]: ").strip().lower()
            if fs in ('ntfs', 'ext', 'ext2', 'ext3', 'ext4'):
                break
            print("  Please enter 'ntfs' or 'ext'.")
    fs = 'ext' if fs and fs.startswith('ext') else 'ntfs'

    # ── open device ──────────────────────────────────────────────────────────
    if args.dry_run:
        print("[DRY RUN] Would open device — skipping actual I/O.")
    else:
        try:
            if args.destructive:
                # Streaming mode omits O_SYNC — a single fdatasync() is called
                # after the full write pass instead, matching badblocks behaviour.
                _w_flags = os.O_RDWR if getattr(args, 'streaming', False) else os.O_RDWR | os.O_SYNC
                fd_w = os.open(args.device, _w_flags)
            fd_r = os.open(args.device, os.O_RDONLY | O_DIRECT)
        except PermissionError:
            print(f"[!] Cannot open {args.device} — run as root.", file=sys.stderr); sys.exit(1)
        except FileNotFoundError:
            print(f"[!] Device not found: {args.device}", file=sys.stderr); sys.exit(1)
        except OSError as e:
            print(f"[!] Open failed: {e}", file=sys.stderr); sys.exit(1)

    align = max(4096, sector_size)

    if not args.dry_run:
        try:
            buf  = AlignedBuf(chunk_bytes, alignment=align)
            wbuf = AlignedBuf(chunk_bytes, alignment=align) if args.destructive else None
        except MemoryError as e:
            print(f"[!] Buffer allocation failed: {e}", file=sys.stderr); sys.exit(1)

        # ── determine range ───────────────────────────────────────────────────
        try:
            dev_bytes = get_device_bytes(fd_r)
        except OSError as e:
            print(f"[!] Could not query device size: {e}", file=sys.stderr); sys.exit(1)

        dev_lbas  = dev_bytes // sector_size
        start_lba = args.start_lba
        end_lba   = args.end_lba if args.end_lba is not None else dev_lbas - 1

        if start_lba < 0 or end_lba >= dev_lbas or start_lba > end_lba:
            print(f"[!] Bad range [{start_lba},{end_lba}] — device has {dev_lbas:,} LBAs",
                  file=sys.stderr); sys.exit(1)
    else:
        dev_bytes = 0
        dev_lbas  = 0
        start_lba = args.start_lba
        end_lba   = args.end_lba if args.end_lba is not None else 0

    # ── resume logic ──────────────────────────────────────────────────────────
    _resume_state_raw = None   # kept for streaming pass-level resume lookup
    resume_chunk     = 0
    resume_bad_lbas  = 0
    resume_slow_lbas = 0
    resume_owned     = True   # may this scan write/clear the resume file?
    if args.resume and not args.dry_run:
        _resume_state_raw = load_resume()
        state = _resume_state_raw
        match = _resume_match(state, args.device, start_lba, end_lba,
                               args.chunk_size, args.destructive,
                               getattr(args, 'streaming', False))
        if match == 'scan':
            resume_chunk     = state.get('chunk_idx', 0)
            resume_bad_lbas  = state.get('bad_lbas',  0)
            resume_slow_lbas = state.get('slow_lbas', 0)
            resumed_lba      = start_lba + resume_chunk * chunk_lbas
            print(f"[+] Resuming from chunk {resume_chunk:,}  (LBA {resumed_lba:,})  "
                  f"bad so far: {resume_bad_lbas:,}  slow so far: {resume_slow_lbas:,}")
        elif match == 'range':
            # Resume file belongs to a different scan step sharing this
            # device/range (e.g. the other pass in a queue). Leave it intact
            # for that scan — don't touch or overwrite it from here.
            resume_owned = False
            print("[i] Resume file exists for a different scan step "
                  "(chunk size/mode mismatch) — leaving it untouched, "
                  "starting this scan fresh.")
        else:
            if state:
                print("[!] Resume file is for a different range — starting fresh.")
                clear_resume()

    total_lbas   = end_lba - start_lba + 1
    total_chunks = (total_lbas + chunk_lbas - 1) // chunk_lbas

    patterns = [
        (pat * chunk_bytes if pat is not None else None, name)
        for pat, name in build_pattern_sequence(args.passes, getattr(args, 'rand_passes', 1))
    ] if args.destructive else []

    # ── unified list mode — output and skip list are the same file ───────────
    unified = bool(
        args.output and args.skip_list and
        Path(args.output).resolve() == Path(args.skip_list).resolve()
    )

    # ── header ────────────────────────────────────────────────────────────────
    print("=" * 64)
    print(f"  heavybad v{VERSION}")
    print("=" * 64)
    if not args.dry_run:
        print(f"  Device       : {args.device}  "
              f"({dev_bytes/(1<<30):.2f} GiB, {dev_lbas:,} LBAs @ {sector_size}B)")
    else:
        print(f"  Device       : {args.device}  [DRY RUN — device not opened]")
    print(f"  Range        : LBA {start_lba:,} – {end_lba:,}  "
          f"({total_lbas:,} LBAs, {total_chunks:,} chunks of {chunk_lbas})")
    _is_streaming = getattr(args, 'streaming', False) and args.destructive
    print(f"  Mode         : {'*** DESTRUCTIVE write/verify (STREAMING) ***' if _is_streaming else '*** DESTRUCTIVE write/verify ***' if args.destructive else 'READ-ONLY probe'}")
    print(f"  Filesystem   : {fs.upper()}  ({'LBA ranges → ntfsmarkbad' if fs == 'ntfs' else 'block numbers → e2fsck -l'})")
    if args.destructive:
        print(f"  Passes       : {len(patterns)}  [{format_pattern_sequence(patterns)}]")
        if _is_streaming:
            print(f"  Verify reads : 1x per chunk  (streaming — single read after full-range fdatasync)")
        else:
            print(f"  Verify reads : {args.verify_reads}x per write  (O_DIRECT)")
    print(f"  Retries      : {args.retries} per sub-range")
    print(f"  Slow ms      : >{args.slow_ms} ms")
    print(f"  Output       : {(args.output + '  [unified list]') if unified else (args.output or '(none)')}")
    print(f"  Slow output  : {args.slow_output or '(merged into --output)' if args.output else '(none)'}")
    print(f"  Log          : {getattr(args, 'log', None) or '(none)'}")
    print(f"  Merge skip   : {'unified list' if unified else ('yes → ' + str(args.skip_list) if getattr(args, 'merge_skip', False) else 'no')}")
    if args.resume and not resume_owned:
        print(f"  Resume       : enabled → {RESUME_FILE}  (owned by another scan step)")
    else:
        print(f"  Resume       : {'enabled → ' + str(RESUME_FILE) if args.resume else 'disabled'}")
    print(f"  Histogram    : {'enabled' if args.histogram else 'disabled'}")
    print(f"  Dry run      : {'YES — no I/O will occur' if args.dry_run else 'no'}")
    if resume_chunk:
        print(f"  Resuming     : chunk {resume_chunk:,} / {total_chunks:,}")
    print("=" * 64)
    print()

    if args.dry_run:
        print("[DRY RUN] Config looks good. Exiting without touching the device.")
        return

    # ── output files ─────────────────────────────────────────────────────────
    # Bad and slow both go to --output by default.
    # --slow-output is optional separate file for users who want the distinction.
    out_f      = OutputWriter(args.output,      fs) if args.output      else None
    slow_out_f = OutputWriter(args.slow_output, fs) if args.slow_output else None

    log = Logger(args.log) if getattr(args, 'log', None) else None
    if log:
        log.write(f"heavybad v{VERSION} — scan started")
        log.write(f"  Device     : {args.device}")
        log.write(f"  Mode       : {'DESTRUCTIVE (STREAMING)' if _is_streaming else 'DESTRUCTIVE' if args.destructive else 'READ-ONLY'}")
        log.write(f"  Range      : LBA {start_lba:,} – {end_lba:,}  ({end_lba - start_lba + 1:,} LBAs)")
        log.write(f"  Chunk      : {chunk_lbas} LBAs")
        log.write(f"  Filesystem : {fs.upper()}")
        log.write(f"  Skip list  : {args.skip_list or '(none)'}")
        log.write(f"  Output     : {args.output or '(none)'}" + ("  [unified list]" if unified else ""))
        log.write(f"  Slow ms    : >{args.slow_ms} ms")
        log.write()

    new_bad:  list[tuple[int,int]] = []
    new_slow: list[tuple[int,int]] = []

    prog = Progress(
        total_chunks - resume_chunk, chunk_lbas, chunk_bytes,
        resume_bad=resume_bad_lbas, resume_slow=resume_slow_lbas,
        temp_poller=TempPoller(args.device),
    )
    hist = Histogram() if args.histogram else None

    # ── interrupt / device-gone handler ──────────────────────────────────────
    interrupted  = [False]
    device_gone  = [False]
    cur_chunk    = [resume_chunk]
    cur_pass     = [0]          # streaming mode: current pattern pass index

    def _save_resume_state():
        state = {
            'device':      args.device,
            'start_lba':   start_lba,
            'end_lba':     end_lba,
            'chunk_size':  args.chunk_size,
            'destructive': args.destructive,
            'streaming':   getattr(args, 'streaming', False),
            'chunk_idx':   cur_chunk[0],
            'bad_lbas':    prog.bad_lbas,
            'slow_lbas':   prog.slow_lbas,
        }
        if getattr(args, 'streaming', False):
            state['stream_pass_idx'] = cur_pass[0]
        save_resume(state)

    def _sigint(sig, frame):
        interrupted[0] = True
        lba = start_lba + cur_chunk[0] * chunk_lbas
        print(f"\n\n[!] Interrupted at chunk {cur_chunk[0]:,}  LBA {lba:,}")
        if args.resume and resume_owned:
            _save_resume_state()
            print(f"    Resume file saved → {RESUME_FILE}")
        elif args.resume and not resume_owned:
            print(f"    (resume file belongs to another scan step — not overwritten; "
                  f"use --start-lba {lba} to continue this scan manually)")
        else:
            print(f"    (--resume not set — use --start-lba {lba} to continue manually)")

    signal.signal(signal.SIGINT, _sigint)

    _streaming = getattr(args, 'streaming', False) and args.destructive

    # ── STREAMING destructive ─────────────────────────────────────────────────
    # Each pattern pass: write entire range (no per-chunk sync) → fdatasync once
    # → verify entire range.  Same I/O model as badblocks -w / h2testw.
    if _streaming:
        # Pass-level resume: find which pattern pass to start from
        _stream_pass_start = 0
        if args.resume and resume_owned and _resume_state_raw:
            _rs = _resume_state_raw
            if (_resume_match(_rs, args.device, start_lba, end_lba,
                               args.chunk_size, args.destructive, True) == 'scan'
                    and _rs.get('streaming')):
                _stream_pass_start = _rs.get('stream_pass_idx', 0)
                if _stream_pass_start:
                    print(f"[+] Streaming resume: starting at pattern pass "
                          f"{_stream_pass_start + 1}/{len(patterns)} "
                          f"({patterns[_stream_pass_start][1]})")
                    print()

        # Flush indices: track how much of new_bad/new_slow has been flushed
        # into the live skip IntervalSet so subsequent phases skip them.
        _skip_flush_bad  = 0
        _skip_flush_slow = 0

        def _flush_to_skip():
            nonlocal _skip_flush_bad, _skip_flush_slow
            for sr_s, sr_e in new_bad[_skip_flush_bad:]:
                skip.add_range(sr_s, sr_e)
            for sr_s, sr_e in new_slow[_skip_flush_slow:]:
                skip.add_range(sr_s, sr_e)
            _skip_flush_bad  = len(new_bad)
            _skip_flush_slow = len(new_slow)

        for pass_idx, (pat_tmpl, pat_name) in enumerate(patterns):
            if pass_idx < _stream_pass_start:
                continue
            if interrupted[0] or device_gone[0]:
                break

            cur_pass[0] = pass_idx
            is_rand     = (pat_tmpl is None)

            # RAND: one os.urandom() tile generated once per pass.  Every chunk
            # in the write phase receives the same bytes; the same buffer object
            # is held in memory and reused for the verify phase — no regeneration
            # needed.  If interrupted and resumed, a fresh tile is generated and
            # the whole pass re-writes before verifying.
            rand_tile = os.urandom(chunk_bytes) if is_rand else None
            if is_rand and log:
                log.write(f"STREAM RAND {pat_name} pass {pass_idx+1}/{len(patterns)}  "
                          f"tile={chunk_bytes:,} B")

            # ── WRITE PHASE ────────────────────────────────────────────────────
            prog.reset(total_chunks)
            prog.set_label(f"WRITE {pat_name} {pass_idx+1}/{len(patterns)}")
            failed_chunks: set[int] = set()   # chunks with write errors → skip verify

            for chunk_idx in range(total_chunks):
                if interrupted[0] or device_gone[0]:
                    break
                cur_chunk[0] = chunk_idx
                if args.resume and resume_owned and chunk_idx % 1000 == 0 and chunk_idx:
                    _save_resume_state()

                lba_s = start_lba + chunk_idx * chunk_lbas
                lba_e = min(lba_s + chunk_lbas - 1, end_lba)
                subranges = get_scan_subranges(lba_s, lba_e, skip)
                skipped   = (lba_e - lba_s + 1) - sum(e - s + 1 for s, e in subranges)
                if skipped:
                    prog.tick(skipped=skipped)
                    if not subranges:
                        prog.advance()
                        continue

                chunk_write_err = False
                for sr_s, sr_e in subranges:
                    if interrupted[0] or device_gone[0]:
                        break
                    real_lbas  = sr_e - sr_s + 1
                    real_bytes = real_lbas * sector_size
                    byte_off   = sr_s * sector_size
                    write_data = rand_tile[:real_bytes] if is_rand else pat_tmpl[:real_bytes]
                    try:
                        os.lseek(fd_w, byte_off, os.SEEK_SET)
                        wbuf.write_from(fd_w, write_data)
                    except OSError as exc:
                        if not os.path.exists(args.device):
                            device_gone[0] = True
                            break
                        chunk_write_err = True
                        new_bad.append((sr_s, sr_e))
                        if out_f:      out_f.write_range(sr_s, sr_e)
                        if log:        log.write(f"BAD   LBA {sr_s:,}–{sr_e:,}  OSError {pat_name} (write): {exc}")
                        if args.verbose:
                            print(f"\n  [BAD]  LBA {sr_s:,}–{sr_e:,}  (write error {pat_name}: {exc})")
                        prog.tick(bad=real_lbas)
                if chunk_write_err:
                    failed_chunks.add(chunk_idx)
                prog.advance()

            if interrupted[0] or device_gone[0]:
                break

            # Flush entire write pass to platter before reading back
            prog.finish()
            print(f"  [sync {pat_name} pass {pass_idx+1}/{len(patterns)}...]", end='', flush=True)
            _fdatasync(fd_w)
            print(" done")

            # Flush write-phase bad/slow into live skip set so verify phase
            # (and all following passes) don't re-visit them.
            _flush_to_skip()
            print()

            # ── VERIFY PHASE ───────────────────────────────────────────────────
            prog.reset(total_chunks)
            prog.set_label(f"VRFY  {pat_name} {pass_idx+1}/{len(patterns)}")

            for chunk_idx in range(total_chunks):
                if interrupted[0] or device_gone[0]:
                    break
                cur_chunk[0] = chunk_idx

                if chunk_idx in failed_chunks:
                    prog.advance()
                    continue

                lba_s = start_lba + chunk_idx * chunk_lbas
                lba_e = min(lba_s + chunk_lbas - 1, end_lba)
                subranges = get_scan_subranges(lba_s, lba_e, skip)
                skipped   = (lba_e - lba_s + 1) - sum(e - s + 1 for s, e in subranges)
                if skipped:
                    prog.tick(skipped=skipped)
                    if not subranges:
                        prog.advance()
                        continue

                for sr_s, sr_e in subranges:
                    if interrupted[0] or device_gone[0]:
                        break
                    real_lbas  = sr_e - sr_s + 1
                    real_bytes = real_lbas * sector_size
                    byte_off   = sr_s * sector_size
                    expected   = rand_tile[:real_bytes] if is_rand else pat_tmpl[:real_bytes]

                    chunk_bad    = False
                    chunk_slow   = False
                    fail_reason  = ""
                    peak_read_ms = 0.0

                    for attempt in range(args.retries + 1):
                        try:
                            os.lseek(fd_r, byte_off, os.SEEK_SET)
                            t0        = time.monotonic()
                            read_back = buf.read_into(fd_r)
                            read_ms   = (time.monotonic() - t0) * 1000
                            if read_ms > peak_read_ms:
                                peak_read_ms = read_ms
                            if hist: hist.record(read_ms)
                            prog.total_reads += 1
                            if read_back[:real_bytes] != expected:
                                fail_reason = f"mismatch on {pat_name} verify"
                                if attempt == args.retries:
                                    chunk_bad = True
                            elif read_ms > args.slow_ms:
                                chunk_slow = True
                                break
                            else:
                                break
                        except OSError as exc:
                            if not os.path.exists(args.device):
                                device_gone[0] = True
                                break
                            fail_reason = f"OSError {pat_name} (verify): {exc}"
                            if attempt == args.retries:
                                chunk_bad = True

                    if device_gone[0]:
                        break

                    if chunk_bad:
                        new_bad.append((sr_s, sr_e))
                        if out_f:      out_f.write_range(sr_s, sr_e)
                        if log:        log.write(f"BAD   LBA {sr_s:,}–{sr_e:,}  {fail_reason}")
                        if args.verbose:
                            print(f"\n  [BAD]  LBA {sr_s:,}–{sr_e:,}  ({fail_reason})")
                        prog.tick(bad=real_lbas)
                    elif chunk_slow:
                        new_slow.append((sr_s, sr_e))
                        if out_f:      out_f.write_range(sr_s, sr_e)
                        if slow_out_f: slow_out_f.write_range(sr_s, sr_e)
                        if log:        log.write(f"SLOW  LBA {sr_s:,}–{sr_e:,}  {peak_read_ms:.0f} ms")
                        if args.verbose:
                            print(f"\n  [SLOW] LBA {sr_s:,}–{sr_e:,}  ({peak_read_ms:.0f} ms)")
                        prog.tick(slow=real_lbas)
                    else:
                        prog.tick()

                prog.advance()

        # Flush verify-phase bad/slow into live skip set so the next
        # pattern pass's write phase skips them from the start.
        if not (interrupted[0] or device_gone[0]):
            _flush_to_skip()

    # ── CHUNK mode (default) ─────────────────────────────────────────────────
    # When _streaming is True the range evaluates to range(N, N) = empty,
    # so this loop is bypassed cleanly without re-indentation.
    for chunk_idx in range(total_chunks if _streaming else resume_chunk, total_chunks):
        if interrupted[0] or device_gone[0]: break

        cur_chunk[0] = chunk_idx

        # Persist resume state every 1000 chunks
        if args.resume and resume_owned and chunk_idx % 1000 == 0 and chunk_idx != resume_chunk:
            _save_resume_state()

        lba_s = start_lba + chunk_idx * chunk_lbas
        lba_e = min(lba_s + chunk_lbas - 1, end_lba)

        # ── split chunk into scannable sub-ranges ─────────────────────────────
        subranges = get_scan_subranges(lba_s, lba_e, skip)
        skipped   = (lba_e - lba_s + 1) - sum(e - s + 1 for s, e in subranges)

        if skipped:
            prog.tick(skipped=skipped)
            if not subranges:
                prog.advance()
                continue

        # ── scan each sub-range ───────────────────────────────────────────────
        for sr_s, sr_e in subranges:
            if interrupted[0] or device_gone[0]: break

            real_lbas  = sr_e - sr_s + 1
            real_bytes = real_lbas * sector_size
            byte_off   = sr_s * sector_size

            chunk_bad    = False
            chunk_slow   = False
            fail_reason  = ""
            read_ms      = 0.0
            peak_read_ms = 0.0       # worst read time seen across all passes/verify reads

            # ── DESTRUCTIVE ───────────────────────────────────────────────────
            if args.destructive:
                sr_patterns = []
                for pat, name in build_pattern_sequence(args.passes, getattr(args, 'rand_passes', 1)):
                    if pat is None:
                        sr_patterns.append((None, name))
                    else:
                        sr_patterns.append((pat * real_bytes, name))

                for pat_full, pat_name in sr_patterns:
                    write_data = os.urandom(real_bytes) if pat_full is None else pat_full[:real_bytes]

                    ok = False
                    for attempt in range(args.retries + 1):
                        try:
                            os.lseek(fd_w, byte_off, os.SEEK_SET)
                            wbuf.write_from(fd_w, write_data)
                            _fdatasync(fd_w)

                            all_reads_ok = True
                            for vr in range(args.verify_reads):
                                os.lseek(fd_r, byte_off, os.SEEK_SET)
                                t0        = time.monotonic()
                                read_back = buf.read_into(fd_r)
                                read_ms   = (time.monotonic() - t0) * 1000
                                if read_ms > peak_read_ms:
                                    peak_read_ms = read_ms
                                if hist: hist.record(read_ms)
                                prog.total_reads += 1

                                if read_back[:real_bytes] != write_data:
                                    fail_reason  = (f"mismatch on {pat_name} "
                                                    f"verify {vr+1}/{args.verify_reads}")
                                    all_reads_ok = False
                                    break
                                if read_ms > args.slow_ms:
                                    chunk_slow = True

                            if all_reads_ok:
                                ok = True; break

                        except OSError as exc:
                            # Check if device disappeared
                            if not os.path.exists(args.device):
                                device_gone[0] = True
                                print(f"\n[!] Device {args.device} disappeared! "
                                      f"Stopping at LBA {sr_s:,}.", file=sys.stderr)
                                break
                            fail_reason = f"OSError {pat_name}: {exc}"

                    if device_gone[0]: break
                    if not ok:
                        chunk_bad = True; break

            # ── READ-ONLY ─────────────────────────────────────────────────────
            else:
                for attempt in range(args.retries + 1):
                    try:
                        os.lseek(fd_r, byte_off, os.SEEK_SET)
                        t0      = time.monotonic()
                        buf.read_into(fd_r)
                        read_ms = (time.monotonic() - t0) * 1000
                        if read_ms > peak_read_ms:
                            peak_read_ms = read_ms
                        if hist: hist.record(read_ms)
                        prog.total_reads += 1
                        if read_ms > args.slow_ms:
                            chunk_slow = True
                        break
                    except OSError as exc:
                        if not os.path.exists(args.device):
                            device_gone[0] = True
                            print(f"\n[!] Device {args.device} disappeared! "
                                  f"Stopping at LBA {sr_s:,}.", file=sys.stderr)
                            break
                        fail_reason = f"OSError: {exc}"
                        if attempt == args.retries:
                            chunk_bad = True

            if device_gone[0]: break

            # ── record results ────────────────────────────────────────────────
            if chunk_bad:
                new_bad.append((sr_s, sr_e))
                if out_f:      out_f.write_range(sr_s, sr_e)        # bad → output
                if slow_out_f: pass                                  # bad not in slow-output
                if log:        log.write(f"BAD   LBA {sr_s:,}–{sr_e:,}  {fail_reason}")
                if args.verbose:
                    print(f"\n  [BAD]  LBA {sr_s:,}–{sr_e:,}  ({fail_reason})")
                prog.tick(bad=real_lbas)

            elif chunk_slow:
                new_slow.append((sr_s, sr_e))
                if out_f:      out_f.write_range(sr_s, sr_e)        # slow → same output
                if slow_out_f: slow_out_f.write_range(sr_s, sr_e)   # also separate if set
                if log:        log.write(f"SLOW  LBA {sr_s:,}–{sr_e:,}  {peak_read_ms:.0f} ms")
                if args.verbose:
                    print(f"\n  [SLOW] LBA {sr_s:,}–{sr_e:,}  ({peak_read_ms:.0f} ms)")
                prog.tick(slow=real_lbas)

            else:
                prog.tick()

        prog.advance()   # exactly one per chunk regardless of sub-range count

    # ── teardown ──────────────────────────────────────────────────────────────
    prog.finish()
    if out_f:      out_f.close()
    if slow_out_f: slow_out_f.close()
    if args.destructive: os.close(fd_w)
    os.close(fd_r)
    del buf
    if wbuf: del wbuf
    if args.resume and resume_owned:
        if not interrupted[0] and not device_gone[0]:
            clear_resume()
            print("[+] Resume file cleared (scan completed cleanly).")
        else:
            _save_resume_state()

    total_bad_lbas  = sum(e - s + 1 for s, e in new_bad)
    total_slow_lbas = sum(e - s + 1 for s, e in new_slow)

    print("─" * 64)
    print(f"  heavybad v{VERSION}  —  scan complete")
    print("─" * 64)
    print(f"  Chunks scanned   : {prog.done:>12,}")
    print(f"  LBAs skipped     : {prog.skip_lbas:>12,}  (known-bad skip list)")
    print(f"  New bad  LBAs    : {total_bad_lbas:>12,}  ({prog.bad_chunks} sub-ranges)")
    print(f"  New slow LBAs    : {total_slow_lbas:>12,}  ({prog.slow_chunks} sub-ranges, >{args.slow_ms} ms)")
    print(f"  Total flagged    : {total_bad_lbas + total_slow_lbas:>12,}  (bad + slow → {args.output or 'not saved'})")
    if args.slow_output and new_slow:
        print(f"  Slow separate    : {args.slow_output}")
    print("─" * 64)

    if log:
        status = "interrupted" if interrupted[0] else ("device gone" if device_gone[0] else "complete")
        log.write()
        log.write(f"SUMMARY  [{status}]")
        log.write(f"  Chunks scanned   : {prog.done:>12,}")
        log.write(f"  LBAs skipped     : {prog.skip_lbas:>12,}  (known-bad skip list)")
        log.write(f"  New bad  LBAs    : {total_bad_lbas:>12,}  ({prog.bad_chunks} sub-ranges)")
        log.write(f"  New slow LBAs    : {total_slow_lbas:>12,}  ({prog.slow_chunks} sub-ranges, >{args.slow_ms} ms)")
        log.write(f"  Total flagged    : {total_bad_lbas + total_slow_lbas:>12,}")
        log.write()
        log.close()

    if hist and prog.total_reads > 0:
        hist.print(prog.total_reads)

    # ── merge new findings into skip list ─────────────────────────────────────
    if getattr(args, 'merge_skip', False) and args.skip_list and not unified and not interrupted[0] and not device_gone[0]:
        print()
        merge_into_skip_list(args.skip_list, args.output or '', args.slow_output or '')

    signal.signal(signal.SIGINT, signal.SIG_DFL)


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # ── queue mode: heavybad.py queue.json ────────────────────────────────────
    if len(sys.argv) == 2 and sys.argv[1].endswith('.json'):
        if os.geteuid() != 0:
            print("[!] Requires root.", file=sys.stderr); sys.exit(1)
        run_queue(sys.argv[1])
        return

    ap = argparse.ArgumentParser(
        prog="heavybad.py",
        description=f"heavybad v{VERSION} — Multi-pass bad-sector detector (Linux, raw block devices)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""heavybad v{VERSION}  —  https://github.com/loverofpizzas/heavybad""",
    )
    ap.add_argument("--version",      action="version", version=f"heavybad {VERSION}")
    ap.add_argument("--device",       required=True, metavar="DEV",
                    help="Block device to scan (e.g. /dev/sda)")
    ap.add_argument("--destructive",  action="store_true",
                    help="Enable write/verify passes. WITHOUT this: read-only probe.")
    ap.add_argument("--start-lba",    type=int, default=0,    metavar="N",
                    help="First LBA to scan (default: 0)")
    ap.add_argument("--end-lba",      type=int, default=None, metavar="N",
                    help="Last LBA to scan inclusive (default: last LBA on device)")
    ap.add_argument("--sector-size",  type=int, default=512,  metavar="B",
                    help="Logical sector size in bytes (default: 512)")
    ap.add_argument("--chunk-size",   type=int, default=8,    metavar="N",
                    help="LBAs per I/O chunk (default: 8). Use 1 for 512B granularity.")
    ap.add_argument("--passes",       type=int, default=4,
                    choices=range(1, 6), metavar="1-5",
                    help="Write patterns for destructive mode (default: 4). Pass 5 = random.")
    ap.add_argument("--rand-passes",  type=int, default=1,    metavar="N",
                    help="Repeat the RAND pattern N times in a row at the end of each "
                         "destructive pass (default: 1). Only applies if --passes 5 "
                         "(RAND included). Stacks the most marginal-sector-sensitive "
                         "pattern without affecting the deterministic 0xAA/0x55/0xFF/0x00 passes.")
    ap.add_argument("--verify-reads", type=int, default=3,    metavar="N",
                    help="O_DIRECT reads per write in destructive mode (default: 3)")
    ap.add_argument("--retries",      type=int, default=0,    metavar="N",
                    help="Retries per sub-range before declaring bad (default: 0)")
    ap.add_argument("--slow-ms",      type=int, default=200,  metavar="MS",
                    help="Read time threshold in ms — slower = flagged (default: 200)")
    ap.add_argument("--fs",           metavar="TYPE", choices=['ntfs','ext','ext2','ext3','ext4'],
                    help="Filesystem type: 'ntfs' (LBA ranges) or 'ext' (block numbers for e2fsck). "
                         "If omitted, you will be prompted at startup.")
    ap.add_argument("--skip-list",    metavar="FILE",
                    help="File of known-bad LBAs/ranges to skip entirely")
    ap.add_argument("--output",       metavar="FILE",
                    help="Append all flagged LBAs (bad + slow) here in real time, as ranges")
    ap.add_argument("--slow-output",  metavar="FILE",
                    help="Also write slow LBAs to a separate file (optional)")
    ap.add_argument("--log",          metavar="FILE",
                    help="Write timestamped log of all bad/slow LBA events and final summary to FILE (append mode)")
    ap.add_argument("--merge-skip",   action="store_true",
                    help="After scan completes, append --output (and --slow-output) to --skip-list")
    ap.add_argument("--resume",       action="store_true",
                    help=f"Save/restore scan progress to {RESUME_FILE}")
    ap.add_argument("--histogram",    action="store_true",
                    help="Print response time histogram at end of scan")
    ap.add_argument("--streaming",    action="store_true",
                    help="Streaming destructive mode: write entire range with one pattern pass, "
                         "fdatasync once, then verify entire range — same I/O model as "
                         "badblocks -w / h2testw.  Reveals marginal sectors that fail only under "
                         "sustained sequential write pressure.  ~3x faster than chunk mode at "
                         "equivalent pass count.  verify-reads is always 1 in this mode.  "
                         "(destructive only)")
    ap.add_argument("--dry-run",      action="store_true",
                    help="Parse args and print config, but do not open or touch the device")
    ap.add_argument("--verbose",      action="store_true",
                    help="Print each bad/slow sub-range as it is found")

    args = ap.parse_args()

    if not args.dry_run and os.geteuid() != 0:
        print("[!] Requires root.", file=sys.stderr); sys.exit(1)

    if args.chunk_size < 1:
        print("[!] --chunk-size must be >= 1", file=sys.stderr); sys.exit(1)

    if args.rand_passes < 1:
        print("[!] --rand-passes must be >= 1", file=sys.stderr); sys.exit(1)

    if getattr(args, 'streaming', False) and not args.destructive:
        print("[!] --streaming requires --destructive.", file=sys.stderr); sys.exit(1)

    if args.rand_passes > 1 and args.passes < 5:
        print("[!] --rand-passes > 1 has no effect unless --passes 5 (RAND included) — ignoring.")
        args.rand_passes = 1

    if getattr(args, 'merge_skip', False) and not args.skip_list:
        print("[!] --merge-skip requires --skip-list to be set.", file=sys.stderr); sys.exit(1)

    if (args.merge_skip and args.skip_list and args.output and
            Path(args.output).resolve() == Path(args.skip_list).resolve()):
        print("[!] --merge-skip is redundant in unified list mode (output == skip-list) — ignoring.")
        args.merge_skip = False

    if args.destructive and not args.dry_run and not getattr(args, 'skip_confirmation', False):
        print("=" * 64)
        print("  WARNING: DESTRUCTIVE MODE")
        print("  All data in the scanned range will be permanently overwritten.")
        print("  Only use this on unallocated/expendable regions.")
        print("=" * 64)
        if input("  Type YES to proceed: ").strip() != "YES":
            print("Aborted."); sys.exit(0)
        print()

    skip = load_skip_list(args.skip_list)
    print()
    scan(args, skip)


if __name__ == "__main__":
    main()
