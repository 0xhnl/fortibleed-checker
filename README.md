# fortibleed-checker

Fortinet leak checker that queries two public datasets to see if a domain or IP appears in the leaked Fortinet VPN credentials corpus.

- **Hudson Rock** — Fortinet-domains dataset (rich domain context: industry, size, leaked URLs, FortiGuard IDs, country).
- **SocRadar fortibleed** — IP-based lookup against the same leak.

## Install

Requires Python 3.8+ and `requests`.

```bash
pip install requests
```

## Usage

```
fortibleed.py (-d DOMAIN | -i IP | -r CIDR | -f FILE) [--json] [-v] [--no-color] [-o FILE]
```

| Flag | Description |
| ---- | ----------- |
| `-d, --domain`  | Domain lookup via Hudson Rock (exact match or subdomain of) |
| `-i, --ip`      | Single IP lookup via SocRadar |
| `-r, --range`   | CIDR range — each host is queried via SocRadar |
| `-f, --file`    | Mixed targets (domain / ip / cidr) one per line |
| `--json`        | Emit raw JSON instead of formatted output |
| `-v, --verbose` | Log requests and decisions to stderr |
| `--no-color`    | Disable ANSI colors |
| `-o, --output`  | Append plain-text (colors stripped) output to a file |

## Examples

```bash
# Domain
./fortibleed.py -d example.com

# Single IP
./fortibleed.py -i 1.2.3.4

# CIDR range
./fortibleed.py -r 192.168.1.0/24

# Mixed file of domains, IPs, and CIDRs
./fortibleed.py -f domain.txt -o output.txt
```

Input file format (`-f`):

```
example.com
1.2.3.4
10.0.0.0/28
# comments and blank lines are skipped
```

## Output

- Plain `[ ]` lines for non-hits.
- Highlighted `[!]` lines (green) for detected leaks.
- File mode prints a summary `[+] Done. N/M detected.` plus the list of hits.

## Acknowledgements

Thanks to **[Hudson Rock](https://www.hudsonrock.com/fortinet)** and **[SocRadar](https://socradar.io/free-tools/fortibleed)** for publishing the datasets and free APIs this tool relies on. This checker is just a thin wrapper around their work.
