#!/usr/bin/env python3
"""
patch_pipeline.py

One file, one command. Does everything patch-maker.py and
run-patches.py did as two separate scripts, in order:

  STEP 1 - Walk the pre-approved patch repository, read every
           metadata.json (skipping anything not APPROVED, and
           re-checking each patch file's sha256 against what was
           recorded at approval time), and roll it all into one
           CVE -> patch catalog (repository/catalog.json).

  STEP 2 - Read vulnerabilities.csv and check each row's CVE against
           that catalog - no fuzzy matching, no guessing. A CVE
           either has an approved patch on file or it doesn't. Saves
           the matches to patch_queue.csv.

  STEP 3 - For every group of hosts that need the same patch, build a
           temporary Ansible inventory and run that package's
           playbook.yml against them.

Because this is all one script now, step 3 uses the matches already
sitting in memory from step 2 - it does NOT need to re-read
patch_queue.csv from disk. That removes the old "forgot to rerun
patch-maker first" trap from the two-script version.

Requirements:
    pip install ansible pyyaml
    # For Windows targets:
    pip install pywinrm
    ansible-galaxy collection install ansible.windows

Usage:
    python3 patch_pipeline.py
"""

import csv
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlparse

import yaml

# ========================================================================
# CONFIGURATION - edit these for your environment
# ========================================================================

# --- Step 1 & 2: building the catalog and matching vulnerabilities.csv ---

REPOSITORY_DIR = Path("repository")
CATALOG_OUTPUT = REPOSITORY_DIR / "catalog.json"
VULNERABILITIES_CSV = Path("vulnerabilities.csv")
PATCH_QUEUE_CSV = Path("patch_queue.csv")

# A metadata.json needs all of these to be usable by the automation.
REQUIRED_FIELDS = [
    "package_name", "operating_system", "approval_status",
    "cves", "patch_file", "fixes_version",
]

# --- Step 3: running the Ansible playbooks ---

# The playbooks fetch the patch by URL (win_get_url), not from a local
# path - so repository/ needs to actually be served over HTTP from
# somewhere the target hosts can reach.
#
# If AUTO_START_PATCH_SERVER is True (the default), this script starts
# `python3 -m http.server` on its own before Step 3 and shuts it down
# afterward - no second terminal needed. Set it to False if you'd
# rather run that server yourself (e.g. it's already running, or
# repository/ is being served from a different machine entirely).
AUTO_START_PATCH_SERVER = True
PATCH_SERVER_BASE_URL = "http://192.168.90.3:8080"
PATCH_SERVER_PORT = urlparse(PATCH_SERVER_BASE_URL).port or 8080

# Wazuh's hostname field (e.g. "WindowsAgent") isn't necessarily
# something Ansible can connect to directly. Map each one to its real
# IP/DNS name here. Anything not listed is used as-is.
HOST_ADDRESS = {
    "WindowsAgent": "192.168.90.2",
}

# Connection variables per OS, written into a temporary inventory for
# each playbook run.
LINUX_VARS = {
    "ansible_user": "youruser",
    "ansible_ssh_private_key_file": "/home/patch-automation/.ssh/id_ed25519",
}

WINDOWS_VARS = {
    "ansible_user": r"digicart-user01\user01",
    "ansible_password": "<YourPassword>",
    "ansible_connection": "winrm",
    "ansible_winrm_transport": "ntlm",
    "ansible_port": "5985",
    "ansible_winrm_server_cert_validation": "ignore",
}


# ========================================================================
# STEP 1 - build the catalog from every metadata.json in the repository
# ========================================================================

def verify_checksum(metadata_path, metadata):
    """Confirms the patch file on disk matches its recorded sha256.

    Returns True if it matches (or there's no checksum recorded to
    check against), False if the file is missing or doesn't match -
    either way, a package that fails this should not enter the
    catalog: an unverified binary should never get picked up silently.
    """
    patch_file = metadata_path.parent / metadata["patch_file"]
    expected = metadata.get("patch_sha256")

    if not expected:
        return True  # nothing recorded to verify against

    if not patch_file.exists():
        print(f"  [WARN] patch file missing: {patch_file}")
        return False

    actual = hashlib.sha256(patch_file.read_bytes()).hexdigest()
    if actual != expected:
        print(f"  [WARN] checksum mismatch for {patch_file}")
        print(f"         expected {expected}")
        print(f"         got      {actual}")
        return False

    return True


def build_catalog():
    """Reads every metadata.json under the repository and builds the
    CVE -> patch catalog, keeping only approved, checksum-verified
    packages."""
    catalog = {}
    stats = {
        "packages": 0, "approved": 0, "not_approved": 0,
        "invalid": 0, "checksum_failed": 0, "cve_entries": 0,
        "cve_conflicts": 0,
    }

    for metadata_path in sorted(REPOSITORY_DIR.rglob("metadata.json")):
        stats["packages"] += 1
        try:
            metadata = json.loads(metadata_path.read_text())
        except json.JSONDecodeError as error:
            print(f"[SKIP] {metadata_path}: invalid JSON ({error})")
            stats["invalid"] += 1
            continue

        missing = [field for field in REQUIRED_FIELDS if not metadata.get(field)]
        if missing:
            print(f"[SKIP] {metadata_path}: missing field(s) {missing}")
            stats["invalid"] += 1
            continue

        if metadata["approval_status"] != "APPROVED":
            print(f"[SKIP] {metadata_path}: status is "
                  f"'{metadata['approval_status']}', not APPROVED")
            stats["not_approved"] += 1
            continue

        if not verify_checksum(metadata_path, metadata):
            stats["checksum_failed"] += 1
            continue

        stats["approved"] += 1
        repo_relative_dir = metadata_path.parent.relative_to(REPOSITORY_DIR)

        for cve in metadata["cves"]:
            if cve in catalog:
                print(f"  [WARN] {cve} already claimed by "
                      f"{catalog[cve]['package_name']} - "
                      f"{metadata['package_name']} also claims it. "
                      f"Keeping the first one; fix this conflict by hand.")
                stats["cve_conflicts"] += 1
                continue

            catalog[cve] = {
                "cve": cve,
                "package_name": metadata["package_name"],
                "operating_system": metadata["operating_system"].lower(),
                "fixes_version": metadata["fixes_version"],
                "patch_file": str(repo_relative_dir / metadata["patch_file"]),
                "patch_sha256": metadata.get("patch_sha256"),
                "playbook_path": str(repo_relative_dir / "playbook.yml"),
                "approved_by": metadata.get("approved_by"),
                "approval_date": metadata.get("approval_date"),
            }
            stats["cve_entries"] += 1

    CATALOG_OUTPUT.write_text(json.dumps(catalog, indent=2))

    print()
    print(f"Scanned {stats['packages']} metadata.json file(s).")
    print(f"  Approved packages:      {stats['approved']}")
    print(f"  Not approved:           {stats['not_approved']}")
    print(f"  Invalid/missing fields: {stats['invalid']}")
    print(f"  Checksum failures:      {stats['checksum_failed']}")
    print(f"  CVE conflicts:          {stats['cve_conflicts']}")
    print(f"Catalog has {stats['cve_entries']} CVE entries -> saved to {CATALOG_OUTPUT}")

    return catalog


# ========================================================================
# STEP 2 - match vulnerabilities.csv against the catalog
# ========================================================================

def os_matches(catalog_os, csv_os):
    """Checks the catalog's short OS name against the CSV's full string.

    e.g. catalog "windows" should match csv "Microsoft Windows 11 Pro
    10.0.26200.9168", and catalog "ubuntu" should match csv
    "Ubuntu 22.04.3 LTS".
    """
    return catalog_os.lower() in (csv_os or "").lower()


def match_patches(catalog):
    """Walks the vulnerability CSV and finds an approved patch for each row."""
    matched = []
    stats = {
        "total": 0, "matched": 0, "no_catalog_entry": 0,
        "os_mismatch": 0, "already_fixed": 0,
    }

    with VULNERABILITIES_CSV.open(newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            stats["total"] += 1
            cve = row["cve"]
            entry = catalog.get(cve)

            if entry is None:
                stats["no_catalog_entry"] += 1
                continue

            if not os_matches(entry["operating_system"], row["os"]):
                stats["os_mismatch"] += 1
                continue

            installed = (row.get("installed_version") or "").strip()
            if installed and installed == entry["fixes_version"]:
                # Scanner may just be reporting a stale finding.
                stats["already_fixed"] += 1
                continue

            matched.append({
                "hostname": row["hostname"],
                "cve": cve,
                "severity": row.get("severity", ""),
                "package_name": entry["package_name"],
                "installed_version": installed,
                "fixes_version": entry["fixes_version"],
                "patch_file": entry["patch_file"],
                "patch_sha256": entry["patch_sha256"],
                "playbook_path": entry["playbook_path"],
            })
            stats["matched"] += 1

    if matched:
        fieldnames = list(matched[0].keys())
        with PATCH_QUEUE_CSV.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(matched)
        print(f"Saved {len(matched)} row(s) to {PATCH_QUEUE_CSV}")
    else:
        print("Nothing matched - no queue file written.")

    print()
    print(f"Checked {stats['total']} vulnerability row(s).")
    print(f"  Matched to an approved patch:  {stats['matched']}")
    print(f"  No catalog entry for that CVE: {stats['no_catalog_entry']}")
    print(f"  OS mismatch:                   {stats['os_mismatch']}")
    print(f"  Already at fixed version:      {stats['already_fixed']}")

    return matched


# ========================================================================
# STEP 3 - run the Ansible playbooks for every matched patch
# ========================================================================

def group_by_playbook(rows):
    """Groups matched rows by playbook.yml path.

    One playbook can apply to several hosts (e.g. every Ubuntu box
    that needs the same jq patch), so each playbook should run once
    per batch, targeting every host that needs it - not once per row.
    Every row in a group shares the same package, so patch_file,
    patch_sha256, fixes_version, and package_name are the same across
    the group too; we just need one copy of each.
    """
    groups = {}
    for row in rows:
        key = row["playbook_path"]
        if key not in groups:
            groups[key] = {
                "hostnames": set(),
                "patch_file": row["patch_file"],
                "patch_sha256": row["patch_sha256"],
                "fixes_version": row["fixes_version"],
                "package_name": row["package_name"],
            }
        groups[key]["hostnames"].add(row["hostname"])
    return groups


def start_patch_server():
    """Starts `python3 -m http.server` in the background, serving
    repository/ so win_get_url/get_url can fetch patch files from it.
    Waits briefly and confirms it actually came up before returning."""
    print(f"Starting patch server on port {PATCH_SERVER_PORT} "
          f"(serving {REPOSITORY_DIR}/)...")
    process = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(PATCH_SERVER_PORT),
         "--directory", str(REPOSITORY_DIR)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    for _ in range(10):
        time.sleep(0.3)
        try:
            urllib.request.urlopen(PATCH_SERVER_BASE_URL, timeout=1)
            print("Patch server is up.")
            return process
        except urllib.error.HTTPError:
            # A real HTTP response, even an error one, still proves
            # the server is up and reachable.
            print("Patch server is up.")
            return process
        except Exception:
            continue

    print("[WARN] couldn't confirm the patch server came up in time - "
          "playbooks may fail to fetch patches. Check nothing else is "
          f"already using port {PATCH_SERVER_PORT}.")
    return process


def stop_patch_server(process):
    print("Stopping patch server...")
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def guess_os(playbook_path):
    """catalog.json stores paths like 'windows/vlc/playbook.yml' or
    'ubuntu/jq/playbook.yml' - the OS is just the first folder."""
    return playbook_path.split("/")[0]


def get_playbook_host_group(playbook_path):
    """Reads a playbook.yml's `hosts:` value.

    Each package's playbook was written independently, so there's no
    guarantee they all target the same inventory group name. Rather
    than guessing one fixed name, read it straight from the file so
    our generated inventory always matches what the play expects.
    """
    try:
        with open(playbook_path) as playbook_file:
            plays = yaml.safe_load(playbook_file)
        group = plays[0].get("hosts")
        if group:
            return str(group)
    except Exception as error:
        print(f"  [WARN] couldn't read 'hosts:' from {playbook_path}: {error}")

    print(f"  [WARN] falling back to inventory group 'all' for {playbook_path} "
          f"- double check this actually matches what the playbook expects.")
    return "all"


def write_inventory(hostnames, os_name, group_name):
    """Writes a temporary INI inventory file for one playbook run,
    using the same group name the playbook's `hosts:` line expects."""
    var_block = WINDOWS_VARS if os_name == "windows" else LINUX_VARS

    lines = [f"[{group_name}]"]
    for hostname in sorted(hostnames):
        address = HOST_ADDRESS.get(hostname, hostname)
        lines.append(f"{hostname} ansible_host={address}")

    lines.append("")
    lines.append(f"[{group_name}:vars]")
    for key, value in var_block.items():
        lines.append(f"{key}={value}")

    inventory_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".ini", delete=False
    )
    inventory_file.write("\n".join(lines))
    inventory_file.close()
    return inventory_file.name


def build_patch_vars(patch_file, patch_sha256, fixes_version, package_name, os_name):
    """Builds the extra-vars the playbooks expect: where to fetch the
    patch from, where to save it, its checksum, and the version/name
    used in reporting steps."""
    url_path = quote(patch_file, safe="/")
    patch_url = f"{PATCH_SERVER_BASE_URL}/{url_path}"
    filename = patch_file.rsplit("/", 1)[-1]

    if os_name == "windows":
        patch_dest = f"C:\\Windows\\Temp\\{filename}"
    else:
        patch_dest = f"/tmp/{filename}"

    return {
        "patch_url": patch_url,
        "patch_dest": patch_dest,
        "patch_sha256": patch_sha256,
        "fixes_version": fixes_version,
        "package_name": package_name,
    }


def run_playbook(playbook_path, group):
    hostnames = group["hostnames"]
    os_name = guess_os(playbook_path)
    full_playbook_path = REPOSITORY_DIR / playbook_path
    group_name = get_playbook_host_group(full_playbook_path)
    inventory_path = write_inventory(hostnames, os_name, group_name)
    extra_vars = build_patch_vars(
        group["patch_file"], group["patch_sha256"],
        group["fixes_version"], group["package_name"], os_name,
    )

    print(f"\n--- Running {full_playbook_path} for {sorted(hostnames)} "
          f"(inventory group: {group_name}) ---")
    print(f"    patch_url:  {extra_vars['patch_url']}")
    print(f"    patch_dest: {extra_vars['patch_dest']}")

    command = ["ansible-playbook", str(full_playbook_path), "-i", inventory_path]
    for key, value in extra_vars.items():
        command += ["-e", f"{key}={value}"]

    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    if result.returncode != 0:
        print(f"FAILED: {playbook_path} (exit code {result.returncode})")
        return False

    # ansible-playbook exits 0 even when zero hosts matched the play,
    # so a clean exit code alone doesn't prove anything actually ran.
    # Confirm each host we asked for shows up in the PLAY RECAP with
    # a real result line before calling it a success.
    ran_for_every_host = all(
        any(line.strip().startswith(host) and "ok=" in line
            for line in result.stdout.splitlines())
        for host in hostnames
    )

    if not ran_for_every_host:
        print(f"WARNING: {playbook_path} exited cleanly but no host actually "
              f"ran - the play's 'hosts: {group_name}' likely still doesn't "
              f"match. Nothing was applied.")
        return False

    print(f"OK: {playbook_path}")
    return True


# ========================================================================
# MAIN - run all three steps back to back
# ========================================================================

def main():
    if shutil.which("ansible-playbook") is None:
        print("ERROR: 'ansible-playbook' was not found on PATH.")
        print("If it's installed in a virtual environment, make sure that's")
        print("activated in this terminal before running the script, e.g.:")
        print("    source .venv/bin/activate")
        print("    python3 patch_pipeline.py")
        sys.exit(1)

    print("== Step 1: building catalog from repository/ ==")
    catalog = build_catalog()

    print()
    print("== Step 2: matching vulnerabilities.csv against the catalog ==")
    matched = match_patches(catalog)

    if not matched:
        print("\nNothing to patch - stopping here.")
        return

    print()
    print("== Step 3: running Ansible playbooks for matched patches ==")
    groups = group_by_playbook(matched)
    print(f"Found {len(groups)} playbook(s) to run across {len(matched)} queued fix(es).")

    server_process = start_patch_server() if AUTO_START_PATCH_SERVER else None
    try:
        succeeded, failed = 0, 0
        for playbook_path, group in groups.items():
            ok = run_playbook(playbook_path, group)
            succeeded += ok
            failed += not ok
    finally:
        if server_process is not None:
            stop_patch_server(server_process)

    print(f"\nDone. {succeeded} playbook(s) succeeded, {failed} failed.")


if __name__ == "__main__":
    main()