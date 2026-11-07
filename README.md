<div align="center">

![VAIN Logo](assets/vain_t.png)

# Vain

**Automated network security and compliance orchestration, from raw Nmap scan to risk-ranked, SIEM-ready findings.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](#docker-recommended)
[![Build](https://img.shields.io/github/actions/workflow/status/v-dll/Vain/tests.yml?branch=main&label=build)](https://github.com/v-dll/Vain/actions)
[![Use](https://img.shields.io/badge/use-authorized%20networks%20only-red)](#legal-disclaimer)

[Overview](#overview) •
[Features](#features) •
[Installation](#installation) •
[Usage](#usage) •
[Configuration](#configuration)

</div>

## Legal Disclaimer

> **Disclaimer:** *Vain is developed solely for authorized network auditing, defensive security research, and educational purposes. Scanning networks without prior explicit consent from the target system owner is illegal and may violate local and international cybersecurity laws. The author assumes no responsibility or liability for unauthorized usage or network disruption caused by this tool.*

Only scan networks you own or have **explicit written permission** to test.

---

## Overview

**Vain** is a lightweight Python pipeline that drives Nmap, sanitizes the raw output, checks every discovered asset against your own YAML security baseline, enriches software versions with live threat intelligence (CVE, CVSS, and EPSS), and delivers the result as a terminal dashboard, an executive HTML report, or structured logs your SIEM can ingest directly.

### Who is it for?

| Audience | How Vain helps |
|---|---|
| **SOC / Blue Teams** | Continuous monitoring, "what changed since yesterday" diffing, and webhook alerts on HIGH/CRITICAL drift. |
| **IT & Sysadmins** | Policy-as-code compliance checks with copy-paste remediation steps. |
| **Vulnerability Management** | Risk-based prioritization using EPSS and asset criticality, not CVSS alone. |
| **Security Learners** | A readable, modular codebase showing how a real defensive pipeline fits together. |

## Features

- **Orchestrated discovery.** Wraps Nmap for host, port, and service-version detection. No need to memorize flags.
- **Safe parsing.** Nmap XML is ingested with `defusedxml` (XXE-hardened) and normalized into strictly validated Pydantic models.
- **Policy-as-code.** Define forbidden ports, mandatory services, and minimum software versions in a YAML baseline. A sensible default baseline is built in.
- **Threat intelligence.** CVEs and CVSS from the **NVD**, plus **EPSS** scores from FIRST to estimate real-world exploit likelihood over the next 30 days.
- **Resilient caching.** A local SQLite cache with TTL sidesteps API rate limits and makes repeat scans fast.
- **Asset criticality.** Map IPs, CIDR blocks, or hostnames to business value; the same finding scores higher on a Domain Controller than on a guest network.
- **Scan diffing.** Compare the current scan against the previous run to surface new open ports and new or resolved findings.
- **Active NSE checks (opt-in).** Add Nmap `default`, `vuln`, and `auth` scripts to test for default credentials, open relays, and known CVEs.
- **Mitigation playbooks.** Each policy rule can carry a `remediation` field that is embedded in the report's "How to fix" column.
- **Multi-format reporting.** Rich terminal tables, a self-contained HTML report (print it to PDF from the browser), JSON-Lines, and CSV.
- **Continuous monitoring.** Watch mode rescans on an interval and pushes Slack, Discord, or generic webhook alerts on serious findings.
- **External exposure check (opt-in).** Check your public IPs against Shodan to catch accidentally exposed services.

> **Modular by design.** Every feature above is an independent plugin. Any one of them can be disabled, replaced, or removed without breaking the rest.

---

## How It Works

```text
Target ──► Nmap scan ──► Parse & validate ──► Analyze (plugins) ──► Display ──► Output (plugins)
```

The core (`scanner.py`, `parser.py`, `pipeline.py`) runs Nmap, parses the XML, and prints discovered hosts and open ports. Every feature (policy checks, CVE/EPSS enrichment, asset criticality, diffing, reports, exports, webhooks, watch mode, Shodan, NSE) is a plugin in `vain/plugins/`, one file per feature.

- Delete a plugin's file to remove its feature, or skip it for one run with `--disable NAME`.
- A plugin that fails to import or crashes while running is reported as a warning; the scan continues.
- `vain plugins` lists what is loaded.

Live enrichment uses the [NVD](https://nvd.nist.gov/developers) and [FIRST EPSS](https://www.first.org/epss/api) APIs, plus [Shodan](https://www.shodan.io/) if enabled. Vain can also analyze an existing Nmap XML file (`--xml`) and work from cached API answers.

Vain actively probes the targets you give it. `--active-scripts` is noisier and may trip IDS/IPS alerts, and aggressive scans can disrupt fragile devices like legacy ICS or printers, so scope carefully. `verify-policy`, `lookup-cve`, and `scan --xml` send nothing to your hosts. Vain never exploits or modifies a target.

`--shodan` sends IP addresses to Shodan (a third party): only publicly routable addresses, meaning scanned hosts that have one plus any `--shodan-ip` you pass. Private addresses (192.168.x.x, 10.x.x.x, ...) are never sent. Leave it off if that is a problem for you.

---

## Requirements

- **OS:** Linux (Debian/Ubuntu, openSUSE, RHEL) or macOS. Windows via WSL2 or Docker.
- **Python:** 3.11 or higher.
- **Nmap:** native `nmap` binary available on your `PATH`.
- **Privileges:** `root` / `sudo` for raw-socket SYN scans and OS fingerprinting.
- **Network:** outbound access to `services.nvd.nist.gov` and `api.first.org` for live enrichment (not needed when working from cache), and `api.shodan.io` if you use `--shodan`.

## Installation

### Docker (recommended)

No Python or Nmap needed on the host.

```bash
git clone https://github.com/v-dll/Vain.git
cd Vain
docker build -t vain .
docker run --rm --net=host \
  -v "$(pwd):/work" \
  -v vain-data:/data \
  vain scan --target 192.168.1.0/24
```

- `-v "$(pwd):/work"` shares your current folder with the container, so reports and exports land in your folder and files like `config/policy.yaml` are found.
- `-v vain-data:/data` keeps the threat-intel cache and scan history between runs.
- `--net=host` lets the container reach your local network directly. It works on **Linux only**; on Docker Desktop (Mac/Windows) the container cannot reach your LAN this way, so install from source instead.
- The container runs as root, which raw-socket scans need.

### From source

```bash
git clone https://github.com/v-dll/Vain.git
cd Vain

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

Verify the installation:

```bash
vain --help
nmap --version
```

Then create editable starter config files in `./config`:

```bash
vain init
```

---

## Usage

> **Running with `sudo`.** The examples below show `sudo vain`. If you installed into a virtual environment, `sudo vain` will not find the command, and `sudo` drops environment variables such as `SHODAN_API_KEY` and `NVD_API_KEY`. Use `sudo -E .venv/bin/vain ...` instead. Root has its own home directory, so the cache and scan history would land in `/root/.vain`; pass `--home ~/.vain` (or set `VAIN_HOME`) to keep them in one place.

### Commands

| Command | Description |
|---|---|
| `vain scan` | Run the full pipeline: discover, parse, analyze, enrich, report. |
| `vain verify-policy` | Run policy checks offline against an existing Nmap XML file. No live scanning. |
| `vain lookup-cve` | Standalone CVE / CVSS / EPSS lookup for a CVE ID or a CPE, no scan required. |
| `vain cache` | `stats`, `purge` (drop expired entries) or `clear` (drop everything) for the local SQLite cache. |
| `vain init` | Write starter `policy.yaml` and `assets.yaml` into `./config`. |
| `vain plugins` | List discovered plugins and whether they loaded. |
| `vain about` | Show the logo, version and author. |

Run `vain` with no command to see the logo and the full help.

### `vain scan` options

**Targets and Nmap**

| Flag | Description |
|---|---|
| `-t`, `--target <ip \| cidr \| range \| host \| file>` | IP, CIDR block, range (`192.168.1.1-50`), hostname, or a text file of targets (one per line). Repeatable. |
| `--xml <file>` | Analyze an existing Nmap XML file instead of scanning. |
| `--ports <spec>` | Ports to scan, e.g. `22,80,443` or `1-1024` (default: top 1000). |
| `--timing <0-5>` | Nmap timing template (default 4). |
| `--os-detect` | Enable OS fingerprinting (needs root). |
| `--no-ping` | Skip host discovery (Nmap `-Pn`). |
| `--allow-large` | Allow scans of more than 65,536 addresses. |
| `--nmap-timeout <sec>` | Stop Nmap after this many seconds (default 3600). |

**Checks and enrichment**

| Flag | Description |
|---|---|
| `--policy <path>` | YAML policy file (default: the bundled baseline). |
| `--assets <path>` | YAML asset-criticality map. |
| `--cve` | Look up CVEs for detected software in the NVD. |
| `--cve-min-cvss <N>` | Ignore CVEs scoring below N (default 7.0). |
| `--cve-max-per-service <N>` | Report at most N CVEs per service, highest CVSS first (default 10). |
| `--epss` | Add EPSS exploit-likelihood scores to findings that have a CVE (from `--cve` or NSE scripts). |
| `--active-scripts` | Append active NSE scripts to the scan. |
| `--nse-scripts <list>` | NSE scripts or categories to run (default `default,vuln,auth`). |
| `--shodan` | Check public IPs against Shodan (needs `SHODAN_API_KEY`). |
| `--shodan-ip <ip>` | Your public / perimeter IP to check. Repeatable. |
| `--cache-ttl <hours>` | How long API answers stay cached (default 24). |
| `--no-cache` | Do not use the on-disk cache. |

**Output, alerting and monitoring**

| Flag | Description |
|---|---|
| `--diff` | Compare against the previous scan and save this one as the new baseline. |
| `--diff-file <file>` | Snapshot file (default: `<home>/last_scan.json`). |
| `--output <file>` | Write an HTML report (e.g. `report.html`). |
| `--export <jsonl \| csv>` | Export machine-readable findings. Repeatable. |
| `--export-file <path>` | Export path (default `vain-findings.jsonl` / `.csv`). |
| `--webhook <url>` | Send alerts to a Slack, Discord, or generic `https://` webhook. |
| `--alert-min-severity <level>` | Lowest severity that triggers an alert (default `HIGH`). |
| `--watch <seconds>` | Re-run continuously, sleeping the given interval between scans (minimum 30). |
| `--fail-on <level>` | Exit with code 1 if any finding is at or above this severity (for CI). |
| `--disable <plugin>` | Turn a plugin off for this run. Repeatable. |
| `-q`, `--quiet` | Do not print result tables (reports and exports still happen). |
| `--home <dir>` | Where Vain stores its cache and scan state (default: `$VAIN_HOME` or `~/.vain`). |

`vain verify-policy` accepts `--xml`, `--policy`, `--fail-on`, `-q` and `--home`.

### Common scenarios

<details open>
<summary><b>Compliance audit of a subnet</b></summary>

```bash
sudo vain scan --target 10.0.0.0/24 --policy config/policy.yaml --output audit.html
```
</details>

<details>
<summary><b>Re-check policy offline from a saved Nmap scan</b></summary>

```bash
vain verify-policy --xml scans/office.xml --policy config/policy.yaml
```
</details>

<details>
<summary><b>"What changed since yesterday?"</b></summary>

```bash
sudo vain scan --target 10.0.0.0/24 --diff
```

The first run saves a baseline; every later run reports new and closed ports and new or resolved findings against the previous run.

</details>

<details>
<summary><b>Risk-based prioritization with asset criticality</b></summary>

```bash
sudo vain scan --target 10.0.0.0/24 \
  --policy config/policy.yaml \
  --assets config/assets.yaml \
  --cve --epss
```

EPSS raises the score of findings that carry a CVE, so pair it with `--cve` (or `--active-scripts`).
</details>

<details>
<summary><b>Look up a CVE without scanning</b></summary>

```bash
vain lookup-cve CVE-2021-44228
vain lookup-cve CVE-2021-44228 --epss
```

</details>

<details>
<summary><b>Active NSE testing (authorized targets only)</b></summary>

```bash
sudo vain scan --target 192.168.1.50 --active-scripts --policy config/policy.yaml
```
</details>

<details>
<summary><b>Export for your SIEM (Splunk, Elastic, Wazuh)</b></summary>

```bash
sudo vain scan --target 10.0.0.0/24 --export jsonl
sudo vain scan --target 10.0.0.0/24 --export csv
```

JSON-Lines output is appended on every run (one event per finding); CSV is rewritten each run.
</details>

<details>
<summary><b>External exposure check</b></summary>

```bash
export SHODAN_API_KEY="your_key"
sudo -E vain scan --target 192.168.1.0/24 --shodan --shodan-ip 203.0.113.7
```

Pass your network's public (perimeter) IP with `--shodan-ip`; Vain does not look it up for you. Private addresses are never sent to Shodan.
</details>

<details>
<summary><b>24/7 monitoring with chat alerts</b></summary>

```bash
sudo vain scan \
  --target 192.168.1.0/24 \
  --policy config/policy.yaml \
  --diff \
  --export jsonl \
  --watch 3600 \
  --webhook "https://discord.com/api/webhooks/<id>/<token>"
```

With `--diff`, alerts are sent only for new findings. Without it, each finding is alerted once per Vain process. Vain has no built-in daemon mode; to run it in the background use Docker (`docker run -d ...`), systemd, or `nohup`.

> The webhook URL contains a secret token. It will appear in your shell history and in the process list, so use a throwaway webhook and rotate it if it leaks.

</details>

---

## Configuration

### Policy file: `config/policy.yaml`

Your security baseline as code.

```yaml
version: "1.0"
rules:
  forbidden_ports:
    - port: 23
      severity: CRITICAL
      description: "Telnet protocol unencrypted exposure."
      remediation: "Run 'systemctl disable telnet.socket' and configure OpenSSH."

  version_checks:
    - service: "OpenSSH"
      min_version: "8.0"
      severity: MEDIUM
```

Rules also support `required_ports` and an optional `scope` list (IPs, CIDR blocks, or hostname globs) on any rule.

Vain scans TCP ports only, so rules are matched against open TCP ports.

A baseline is built into the package (`vain/data/default_policy.yaml`) and is used whenever you do not pass `--policy`. Run `vain init` to copy it to `config/policy.yaml` so you can edit it.

### Asset criticality: `config/assets.yaml`

Map IPs, CIDR blocks, or hostname globs to business value. The evaluator applies a multiplier to the final risk score, escalating findings on core infrastructure and downgrading them on low-value assets. The most specific match wins (exact IP, then hostname, then the smaller CIDR block).

```yaml
version: "1.0"
default_criticality: MEDIUM
assets:
  - match: 192.168.1.10
    name: Domain Controller
    criticality: CRITICAL
  - match: 192.168.1.0/28
    name: Core servers
    criticality: HIGH
  - match: "db-*.corp.example"
    name: Production databases
    criticality: CRITICAL
  - match: 192.168.50.0/24
    name: Guest Wi-Fi
    criticality: LOW
```

Criticality levels and multipliers: `CRITICAL` x1.5, `HIGH` x1.25, `MEDIUM` x1.0, `LOW` x0.6, `MINIMAL` x0.4. Hosts that match no entry use `default_criticality`.

### Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `NVD_API_KEY` | Optional | Raises NVD rate limits for faster lookups. |
| `SHODAN_API_KEY` | Only with `--shodan` | Authenticates Shodan queries. |
| `VAIN_HOME` | Optional | Where Vain stores its cache and scan state (default `~/.vain`). |

### Threat-intel cache

CVE, EPSS and Shodan responses are cached in a local SQLite database (`<home>/cache.sqlite`) with a TTL. Manage it with:

```bash
vain cache stats   # entries, expired entries, size, and entries per namespace
vain cache purge   # drop expired entries
vain cache clear   # wipe everything (add --namespace nvd|epss|shodan to limit it)
```

---

## Troubleshooting

- **`nmap: command not found`:** install Nmap, or use the Docker image.
- **Permission denied on scans:** run with `sudo`, or use Docker with `--net=host` (Linux only).
- **`sudo: vain: command not found`:** you installed into a virtual environment. Use `sudo -E .venv/bin/vain ...`.
- **NVD `403` / `429` errors:** set `NVD_API_KEY` and rely on the cache.
- **`--shodan` needs `SHODAN_API_KEY`:** `sudo` drops environment variables, so use `sudo -E`.
- **No webhook alerts:** check the full URL (it must be `https://`); only findings at or above `--alert-min-severity` (default HIGH) alert, and with `--diff` only new ones.

## Contributing

Contributions are welcome: bug fixes, new policy rules, report templates, and new plugins.

1. Fork the repository and create a feature branch.
2. Keep new functionality **self-contained** (one file in `vain/plugins/`, no imports of other plugins); Vain's features are designed to be swappable.
3. Add or update tests and make sure `pytest` passes.
4. Open a pull request describing the change and its motivation.

Found a security issue in Vain itself? Please report it privately; see [SECURITY.md](SECURITY.md).

## License

Released under the [MIT License](LICENSE). Free to use, modify, and distribute, with no warranty.

**Scan responsibly. Only audit what you're authorized to audit.**
