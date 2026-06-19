# heavybad
**heavybad.py v1.0.8** — Multi-pass bad-sector detector for Linux raw block devices.
Scans drives at the LBA level using O_DIRECT reads and write/verify passes to find and map bad or slow sectors. Supports skip lists to avoid re-scanning known-bad regions, making repeat passes fast. Designed for use on unallocated or expendable regions. Requires root.

## Features
- **Read-only mode** (default) — O_DIRECT probe, safe on live/mounted data
- **Destructive mode** — up to 5 write patterns (0xAA, 0x55, 0xFF, 0x00, RAND) with configurable verify reads per write
- **Streaming mode** — write entire range then verify entire range per pass, matching the I/O model of `badblocks -w` / h2testw; reveals marginal sectors that only fail under sustained sequential write pressure; ~3× faster than chunk mode; write phase uses O_DIRECT so each chunk write is timed — slow writes are flagged immediately and the chunk still reaches verify where it can be upgraded to BAD; newly found bad/slow sectors are flushed into the live skip set after each half-pass
- **RAND as the final net** — the random pattern catches marginal sectors that uniform patterns miss
- **--rand-passes** — repeat the RAND pattern N times in a row at the end of a destructive pass for extra stress on marginal sectors, without touching the deterministic 0xAA/0x55/0xFF/0x00 passes
- **Sub-range splitting** — skips only confirmed bad LBAs within a chunk, not the entire chunk
- **Skip list support** — provide a list of already-known bad LBAs/ranges to skip entirely, saving time on repeat runs
- **Real-time range output** — bad and slow sectors written to file as `start end` ranges (NTFS) or flat block numbers (ext) as they are found
- **--merge-skip** — automatically appends new findings to your skip list at the end of each scan
- **Unified List** — if `--output` and `--skip-list` point to the same file, newly flagged sectors are appended directly onto the skip list, combining both roles into a single file
- **Queue mode** — run multiple scans back to back from a JSON config, with optional infinite looping and automatic skip list updating between passes
- **Resume** — saves progress to `heavybad.resume` every 1000 chunks and on Ctrl+C, restoring counts and position on next run. Resume state is matched per scan step (device, range, chunk size, mode, and streaming flag), so a queue with multiple scan types resumes the correct one. In streaming mode, bad/slow LBA totals are preserved across phases; skip LBA count resets each phase
- **Logging** — `--log FILE` writes a timestamped record of every bad/slow LBA event and a full summary to a file in append mode, accumulating across queue runs
- **Temperature monitoring** — polls drive temperature via `smartctl` every 30 seconds, displayed in the progress line
- **Response time histogram** — buckets every read into 0–50ms / 50–200ms / 200–500ms / 500ms+ at end of scan
- **Filesystem-aware output** — `--fs ntfs` writes LBA ranges for ntfsmarkbad, `--fs ext` writes block numbers for e2fsck

## Requirements
- Linux
- Python 3.10+
- Root access
- `smartctl` (optional, for temperature — part of `smartmontools`)

## Recommended Workflow

### NTFS
1. Read-only pass (`--chunk-size 1`) to map all bad/slow sectors at 512B granularity
2. Inject output into `$BadClus` via [ntfsmarkbad](https://github.com/jamersonpro/ntfsmarkbad)
3. Destructive pass (`--chunk-size 4096`, 5 passes, 3 verify reads) to stress-test remaining sectors
4. Repeat until no new bad sectors are found

### ext2/3/4
1. Read-only pass (`--chunk-size 1`) to map all bad/slow sectors at 512B granularity
2. Inject output into the bad blocks inode via `e2fsck -l bad.txt /dev/sdXN`
3. Destructive pass (`--chunk-size 4096`, 5 passes, 3 verify reads) to stress-test remaining sectors
4. Repeat until no new bad sectors are found

### Late-stage rehab (mostly clean drive)
Once destructive passes consistently come back with 0 new bad sectors, you can lean harder on destructive passes (which do the actual stressing) and run read-only passes less often — e.g. several destructive passes per read pass. Bumping `--verify-reads` and using `--rand-passes` to stack extra RAND passes can help surface the last marginal sectors faster.

### Finding marginal sectors fast (`--streaming`)
If a write-verify tool like h2testw finds bad sectors that chunk-mode passes missed, use `--streaming`. It writes the full range in one sustained burst (no per-chunk sync), matching the I/O pattern that exposes marginal sectors under real write pressure. Good uses:
- Quick diagnostic pass to find marginals before committing to a long chunk-mode run
- Main rehab loop once the drive is nearly clean and you need fast iterations

Because streaming mode does one read per chunk in the verify phase (vs. `--verify-reads` in chunk mode), it's less thorough per pass but covers the range ~3× faster. A typical streaming run with `--passes 5 --rand-passes 2` takes roughly the same wall time as a chunk-mode run with `--passes 1`.

## Examples
```bash
# Read-only precision scan (NTFS)
sudo python3 heavybad.py \
  --device /dev/sda \
  --start-lba 2048 --end-lba 346791935 \
  --chunk-size 1 --slow-ms 150 --fs ntfs \
  --skip-list known_bad.txt \
  --output found_bad.txt \
  --merge-skip --resume --histogram --verbose

# Destructive stress test (NTFS)
sudo python3 heavybad.py \
  --device /dev/sda --destructive \
  --start-lba 2048 --end-lba 346791935 \
  --chunk-size 4096 --passes 5 --verify-reads 3 --fs ntfs \
  --skip-list known_bad.txt \
  --output found_bad.txt \
  --merge-skip --resume --histogram --verbose

# Destructive stress test with extra RAND passes (late-stage rehab)
sudo python3 heavybad.py \
  --device /dev/sda --destructive \
  --start-lba 2048 --end-lba 346791935 \
  --chunk-size 4096 --passes 5 --rand-passes 4 --verify-reads 5 --fs ntfs \
  --skip-list known_bad.txt \
  --output found_bad.txt \
  --merge-skip --resume --histogram --verbose

# Streaming scan — fast marginal sector detection (same I/O model as h2testw)
sudo python3 heavybad.py \
  --device /dev/sda --destructive --streaming \
  --start-lba 2048 --end-lba 346791935 \
  --chunk-size 4096 --passes 5 --rand-passes 2 --fs ntfs \
  --skip-list known_bad.txt \
  --output found_bad.txt \
  --merge-skip --resume --log scan.log

# With logging
sudo python3 heavybad.py \
  --device /dev/sda \
  --start-lba 2048 --end-lba 346791935 \
  --chunk-size 1 --slow-ms 150 --fs ntfs \
  --skip-list known_bad.txt \
  --output found_bad.txt \
  --log scan.log --resume --histogram

# Dry run — validate your command without touching the drive
sudo python3 heavybad.py \
  --device /dev/sda \
  --start-lba 2048 --end-lba 346791935 \
  --chunk-size 1 --dry-run

# Queue mode — run multiple passes unattended
sudo python3 heavybad.py queue.json
```

## Queue Mode
Create a `queue.json` file to run multiple scans sequentially and unattended. After each scan, its output is automatically appended to the skip list before the next scan starts.

```json
{
    "device": "/dev/sda",
    "skip_list": "/path/to/known_bad.txt",
    "fs": "ntfs",
    "resume": true,
    "log": "/path/to/scan.log",
    "repeat": true,
    "scans": [
        {
            "mode": "read",
            "chunk_size": 1,
            "slow_ms": 150,
            "start_lba": 2048,
            "end_lba": 346791935,
            "output": "/path/to/found_bad.txt",
            "histogram": true,
            "verbose": true
        },
        {
            "mode": "destructive",
            "chunk_size": 4096,
            "passes": 5,
            "rand_passes": 4,
            "verify_reads": 3,
            "slow_ms": 150,
            "start_lba": 2048,
            "end_lba": 346791935,
            "output": "/path/to/found_bad.txt",
            "histogram": true,
            "verbose": true
        }
    ]
}
```

`"repeat": true` loops endlessly until Ctrl+C. `"repeat": 3` loops exactly 3 times.

Top-level keys `resume`, `log`, `rand_passes`, and `streaming` apply to all scans. All can be overridden per-scan.

If any scan in the queue is destructive, you are asked to confirm **once** at startup — the queue then runs fully unattended.

If a queue run is interrupted, rerunning `queue.json` with `--resume`/`"resume": true` will skip any scans that already completed and resume the interrupted one from where it left off — resume state is matched against each scan's device, range, chunk size, mode, and streaming flag, so it can't be misapplied to a different scan step.

## Skip List Format
One entry per line:
```
12345
12345 67890
12345-67890
# comment
```
Single LBAs, space-separated ranges, or dash-separated ranges are all accepted.

## Flags
| Flag | Default | Description |
|---|---|---|
| `--device` | required | Block device to scan (e.g. `/dev/sda`) |
| `--destructive` | off | Enable write/verify passes. Without it: read-only probe |
| `--streaming` | off | Streaming destructive mode: write entire range then verify entire range per pass. Matches the I/O model of `badblocks -w` / h2testw — finds marginals that fail under sustained write pressure. Write phase uses O_DIRECT for real per-write timing; slow writes are flagged and still verified. ~3× faster than chunk mode. `--verify-reads` is not used. Requires `--chunk-size` to be a multiple of 8. (destructive only) |
| `--start-lba` | `0` | First LBA to scan |
| `--end-lba` | last LBA | Last LBA to scan inclusive |
| `--sector-size` | `512` | Logical sector size in bytes |
| `--chunk-size` | `8` | LBAs per I/O. Use `1` for 512B granularity (most precise) |
| `--passes` | `4` | Write patterns 1–5 (destructive only). Pass 5 = RAND |
| `--rand-passes` | `1` | Repeat the RAND pattern N times in a row at the end of each destructive pass (destructive only, requires `--passes 5`) |
| `--verify-reads` | `3` | O_DIRECT reads per write (destructive chunk mode only; not used in streaming mode) |
| `--retries` | `0` | Retries per sub-range before declaring bad |
| `--slow-ms` | `200` | Read time threshold in ms — slower gets flagged |
| `--fs` | prompt | Filesystem type: `ntfs` or `ext` (ext2/3/4) |
| `--skip-list` | none | File of known-bad LBAs/ranges to skip entirely |
| `--output` | none | Append all flagged LBAs (bad + slow) in real time |
| `--slow-output` | none | Also write slow LBAs to a separate file (optional) |
| `--log` | none | Write timestamped bad/slow events and final summary to FILE (append mode) |
| `--merge-skip` | off | Append output to skip list after clean scan completes |
| `--resume` | off | Save/restore progress to `heavybad.resume` |
| `--histogram` | off | Print response time histogram at end of scan |
| `--dry-run` | off | Print config without opening or touching the device |
| `--verbose` | off | Print each bad/slow sub-range as it is found |
| `--version` | — | Print version and exit |

## Credits
loverofpizzas — concept, design, testing, and the obsessive drive recovery rabbit hole that made this necessary.

[Claude](https://claude.ai) (Anthropic) — implementation assistance and rubber duck.
