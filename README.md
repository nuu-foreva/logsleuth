# LogSleuth

[![CI](https://github.com/nuu-foreva/logsleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/nuu-foreva/logsleuth/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A small command-line tool that reads application log files and tells you what went wrong:
how many errors there were, which ones keep repeating, and when they clustered together.

It has **no runtime dependencies** (standard library only) and is fully type-annotated.

## Features

- **Robust parser**: handles `,`/`.` fractional seconds, `T` or space separators, level aliases
  (`WARN`, `FATAL`), CRLF line endings, UTF-8 BOMs and undecodable bytes. Stack traces are attached
  to the record that produced them, and unparseable lines are counted instead of crashing the run.
- **Error grouping**: similar errors are collapsed into one signature by masking numbers, IP
  addresses, hex values and UUIDs, so `Timeout after 100ms` and `Timeout after 250ms` count together.
- **Burst detection**: finds clusters of errors inside a sliding time window (default: 5 errors in
  60 seconds) using a single linear pass.
- **Filtering**: by minimum level, source, text, and time range.
- **Two output formats**: readable ASCII text, or JSON for scripts.
- Reads from a file or from standard input, and plays nicely with pipes (`| head`).

## Installation

```bash
git clone https://github.com/nuu-foreva/logsleuth.git
cd logsleuth
python -m pip install .
```

For development (adds the linter):

```bash
python -m pip install -e ".[dev]"
```

## Usage

```bash
logsleuth report sample_logs/app.log
```

```text
LogSleuth report
================
Entries analysed : 29
Malformed lines  : 2 (skipped)
Period           : 2026-10-13 08:00:01 -> 2026-10-13 11:30:00 (3:29:58)
Error rate       : 41.4% (12 of 29 are ERROR or CRITICAL)

Levels
  DEBUG         2  #####
  INFO         12  ##############################
  WARNING       3  ########
  ERROR        11  ############################
  CRITICAL      1  ##

Sources
  api          9  ##############################
  db           7  #######################
  auth         6  ####################
  app          3  ##########
  cache        2  #######
  payments     2  #######

Top errors
  1. 4x [db] Connection timed out after <n>ms (host=<ip>)
     first seen 2026-10-13 09:14:05, last seen 2026-10-13 09:14:31
  2. 2x [auth] Failed login for user=admin ip=<ip>
     first seen 2026-10-13 08:20:19, last seen 2026-10-13 08:20:21
  3. 2x [api] Unhandled exception in GET /orders
     first seen 2026-10-13 09:14:18, last seen 2026-10-13 09:14:38
  4. 2x [payments] Card declined for order=<n> code=<n>
     first seen 2026-10-13 10:44:58, last seen 2026-10-13 10:45:40
  5. 1x [auth] Failed login for user=root ip=<ip>
     first seen 2026-10-13 08:20:23, last seen 2026-10-13 08:20:23

Error bursts (>= 5 errors within 60s)
  2026-10-13 09:14:05 -> 2026-10-13 09:14:44  7 errors

Activity by hour
  08:00    13  ##############################
  09:00    10  #######################
  10:00     4  #########
  11:00     2  #####
```

### Commands

| Command | What it does |
| --- | --- |
| `logsleuth report FILE` | Summary: levels, sources, top errors, bursts, hourly activity |
| `logsleuth grep FILE` | Print the entries that match the filters (multi-line records stay whole) |

Use `-` as `FILE` to read from standard input.

### Filters (both commands)

| Option | Meaning |
| --- | --- |
| `--min-level LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL` (aliases `WARN`, `FATAL` work too) |
| `--source NAME` | Only entries from this source (case-insensitive) |
| `--contains TEXT` | Only messages containing this text (case-insensitive) |
| `--since TIME` / `--until TIME` | Inclusive time range. `YYYY-MM-DD` means midnight; or `YYYY-MM-DDTHH:MM:SS` |

### `report` options

| Option | Default | Meaning |
| --- | --- | --- |
| `--format text\|json` | `text` | Output format |
| `--top N` | `5` | How many recurring errors to list |
| `--burst-window SECONDS` | `60` | Window used for burst detection |
| `--burst-threshold N` | `5` | Errors inside the window needed to count as a burst |

### Examples

```bash
# Every error from the API service, with stack traces
logsleuth grep app.log --min-level ERROR --source api

# How many "timed out" messages happened this morning?
logsleuth grep app.log --contains "timed out" --since 2026-10-13 --until 2026-10-13T12:00:00 --count

# Machine-readable report, tighter burst definition
logsleuth report app.log --format json --burst-window 10 --burst-threshold 3

# Works in a pipeline
kubectl logs my-pod | logsleuth report -
```

## Log format

Each record starts with a header line:

```text
YYYY-MM-DD HH:MM:SS[,mmm] LEVEL source: message
```

Any line that is not a header (a stack trace, for example) is attached to the previous record.
A line is counted as *malformed* and skipped if it appears before the first record, or if its header
has an impossible timestamp such as `2026-13-45 99:00:00`.

Exit codes: `0` success, `1` the input could not be read, `2` invalid usage.

## Project layout

```text
src/logsleuth/
  models.py     LogEntry dataclass and level helpers
  parser.py     text -> LogEntry objects (regex header + continuation lines)
  analyzer.py   filtering, summary, error grouping, burst detection
  report.py     text / JSON rendering
  cli.py        argparse interface
tests/          unittest suite (parser, analysis, rendering, CLI)
sample_logs/    a small realistic log to try the tool on
```

The parsing, analysis and rendering layers are separate pure functions, so the library can be used
without the CLI:

```python
from logsleuth.parser import parse_file
from logsleuth.analyzer import find_error_bursts, top_errors

result = parse_file("sample_logs/app.log")
print(top_errors(result.entries, limit=3))
print(find_error_bursts(result.entries, window_seconds=60, threshold=5))
```

## Development

```bash
python -m unittest discover -s tests -v   # run the tests
ruff check .                              # lint
```

Continuous integration runs both on Python 3.10 through 3.13.

## Design notes and limitations

- **Timestamps are naive.** Log lines are read exactly as written; time zones are neither parsed nor
  converted, so `--since`/`--until` values must not include an offset.
- **Error signatures use the first line only.** This keeps one failing code path from being split by
  differing stack traces. Values that look like words (`user=admin`) are intentionally not masked.
- **Bursts are greedy and non-overlapping.** A burst begins at the first unclaimed error and absorbs
  everything within the window, which is simple, predictable, and `O(n)` after sorting.
- **Memory.** Entries are held in memory, which is fine for typical application logs.

## License

[MIT](LICENSE)
