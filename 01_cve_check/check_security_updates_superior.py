#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Checks for Ubuntu security updates, identifies CVEs fixed between the
current and candidate versions, retrieves their CVSS scores from NVD (using
an in-memory cache), and presents the results in a summary table.
"""

import subprocess
import sys
import os
import re
import json
import time
import requests # type: ignore
from typing import List, Dict, Tuple, Optional, Any

# --- Constants ---
NVD_API_DELAY_SECONDS: float = 6.1
NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUESTS_TIMEOUT_SECONDS: tuple[float, float] = (10, 25)
APT_COMMAND: str = "apt"
SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0,
}

# --- In-Memory CVE Cache ---
# Stores {cve_id: (score, severity, version)}
CVE_SCORE_CACHE: Dict[str, Tuple[Optional[float], Optional[str], Optional[str]]] = {}

# --- Logging Functions --- 
def log_info(message: str) -> None:
    print(f"[INFO] {message}", file=sys.stdout)

def log_warn(message: str) -> None:
    print(f"[WARN] {message}", file=sys.stderr)

def log_error(message: str) -> None:
    print(f"[ERROR] {message}", file=sys.stderr)

def fail(message: str, exit_code: int = 1) -> None:
    log_error(message)
    sys.exit(exit_code)

# --- Helper Functions --- (Keep check_dependencies, ensure_root, update_package_lists)
def check_dependencies() -> None:
    dependencies = ["apt", "apt-get", "grep"]
    apt_found = False
    for dep in dependencies:
        try:
            # Corrected subprocess call
            subprocess.run([dep, "--version"], check=True, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if dep in ["apt", "apt-get"]:
                apt_found = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            fail(f"Required command '{dep}' not found or failed. Please install it.")
        except Exception as e:
            fail(f"Error checking dependency '{dep}': {e}")
    if not apt_found:
         fail("'apt' or 'apt-get' command not found. Is this an APT-based system?")

def ensure_root() -> None:
    if os.geteuid() != 0:
        log_info("Script needs root privileges for APT operations. Re-running with sudo...")
        try:
            args = ['sudo', sys.executable] + sys.argv
            os.execvp('sudo', args)
        except Exception as e:
            fail(f"Failed to re-execute with sudo: {e}")
        fail("execvp failed unexpectedly after attempting sudo.")

def update_package_lists() -> None:
    log_info("Updating package lists...")
    try:
        result = subprocess.run(["apt-get", "update", "-qq"], capture_output=True, text=True)
        if result.returncode != 0:
            log_error(f"apt-get update failed (code {result.returncode}):\n{result.stderr}")
            fail("Failed to update package lists. Check APT configuration and network.")
    except FileNotFoundError:
        fail("'apt-get' command not found.")
    except Exception as e:
        fail(f"An unexpected error occurred during apt-get update: {e}")
    log_info("Package lists updated successfully.")


# --- NVD and Changelog Functions ---

def get_cvss_score(cve_id: str) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """
    Fetches CVSS data for a given CVE from the NVD API, using an in-memory cache.

    Args:
        cve_id: The CVE identifier string.

    Returns:
        A tuple containing (score, severity, version) or (None, None, None).
    """
    global CVE_SCORE_CACHE # Indicate we are using the global cache

    # 1. Check cache first
    if cve_id in CVE_SCORE_CACHE:
        print(f"[INFO] Cache hit for {cve_id}.", file=sys.stderr)
        return CVE_SCORE_CACHE[cve_id]

    # 2. Cache miss - proceed with API call
    print(f"[INFO] Querying NVD for {cve_id}...", file=sys.stderr)
    api_url = f"{NVD_API_BASE_URL}?cveId={cve_id}"
    result: Tuple[Optional[float], Optional[str], Optional[str]] = (None, None, None) # Default failure

    try:
        response = requests.get(api_url, timeout=REQUESTS_TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()

        if not data.get('vulnerabilities'):
            log_warn(f"CVE {cve_id} not found or no vulnerability data in NVD response.")
            # Cache the failure (None, None, None)
            CVE_SCORE_CACHE[cve_id] = result
            return result

        vuln = data['vulnerabilities'][0]['cve']
        metrics = vuln.get('metrics', {})

        # Try v3.1
        cvss_v31 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
        if cvss_v31 and 'baseScore' in cvss_v31 and 'baseSeverity' in cvss_v31:
            result = (float(cvss_v31['baseScore']), str(cvss_v31['baseSeverity']).upper(), "v3.1")
        else:
            # Try v3.0
            cvss_v30 = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {})
            if cvss_v30 and 'baseScore' in cvss_v30 and 'baseSeverity' in cvss_v30:
                 result = (float(cvss_v30['baseScore']), str(cvss_v30['baseSeverity']).upper(), "v3.0")
            else:
                # Try v2.0
                cvss_v2 = metrics.get('cvssMetricV2', [{}])[0]
                cvss_v2_data = cvss_v2.get('cvssData', {})
                if cvss_v2_data and 'baseScore' in cvss_v2_data:
                    score_v2 = float(cvss_v2_data['baseScore'])
                    severity_v2 = str(cvss_v2.get('baseSeverity', 'UNKNOWN')).upper() # v2 severity is higher level
                    result = (score_v2, severity_v2, "v2.0")
                else:
                    log_warn(f"No recognized CVSS score found for {cve_id}.")
                    # result remains (None, None, None)

    except requests.exceptions.Timeout:
        log_warn(f"Timeout fetching NVD data for {cve_id}.")
        # result remains (None, None, None) - cache this failure state
    except requests.exceptions.RequestException as e:
        log_warn(f"Error fetching NVD data for {cve_id}: {e}")
        # result remains (None, None, None) - cache this failure state
    except json.JSONDecodeError:
        log_warn(f"Failed to parse JSON response from NVD for {cve_id}.")
        # result remains (None, None, None) - cache this failure state
    except (KeyError, IndexError, TypeError) as e:
         log_warn(f"Unexpected NVD data structure or type for {cve_id}: {e}")
         # result remains (None, None, None) - cache this failure state
    except Exception as e:
        log_warn(f"An unexpected error occurred processing NVD data for {cve_id}: {e}")
        # result remains (None, None, None) - cache this failure state

    # 3. Store result (success or failure) in cache BEFORE returning
    CVE_SCORE_CACHE[cve_id] = result

    # 4. Return the result found or the default (None, None, None)
    return result


# --- find_cves_in_changelog_range function remains the same ---
def find_cves_in_changelog_range(package: str, old_version: str, new_version: str) -> List[str]:
    """
    Parses apt changelog for unique CVEs between versions. Logs to stderr.
    
    Args:
        package: The name of the package.
        old_version: The currently installed version string.
        new_version: The candidate update version string.

    Returns:
        A sorted list of unique CVE identifier strings found in the range.
        Returns an empty list if errors occur or no CVEs are found.
    """
    def _log_info_stderr(msg): print(f"[INFO] {msg}", file=sys.stderr)
    def _log_warn_stderr(msg): print(f"[WARN] {msg}", file=sys.stderr)

    _log_info_stderr(f"Fetching changelog for {package}...")
    try:
        result = subprocess.run(["apt-get", "changelog", package], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            _log_warn_stderr(f"'apt-get changelog {package}' failed (code {result.returncode}). Stderr: {result.stderr or 'N/A'}")
            return []
        if not result.stdout:
             _log_warn_stderr(f"Changelog for {package} is empty.")
             return []
        changelog = result.stdout
    except FileNotFoundError:
        _log_warn_stderr(f"'apt-get' command not found.")
        return []
    except Exception as e:
        _log_warn_stderr(f"Error fetching changelog for {package}: {e}")
        return []

    cves_in_range: set[str] = set()
    collecting_cves: bool = False
    version_regex = re.compile(r"^\S+\s+\(([^)]+)\)\s+.*")
    cve_regex = re.compile(r"CVE-\d{4}-\d+")

    _log_info_stderr(f"Parsing changelog for CVEs between {old_version} and {new_version}...")
    for line in changelog.splitlines():
        clean_line = line.rstrip('\r')
        match = version_regex.match(clean_line)
        if match:
            entry_version = match.group(1)
            if entry_version == new_version:
                _log_info_stderr(f"  (Changelog: Found entry for new version {new_version}, starting CVE collection)")
                collecting_cves = True
            elif entry_version == old_version:
                _log_info_stderr(f"  (Changelog: Found entry for current version {old_version}, stopping CVE collection)")
                collecting_cves = False
                break
        if collecting_cves:
            found_cves = cve_regex.findall(clean_line)
            cves_in_range.update(found_cves)

    if not cves_in_range:
        _log_info_stderr(f"No CVE identifiers found in changelog between {old_version} and {new_version}.")
        return []
    else:
        return sorted(list(cves_in_range))


# --- Table Formatting --- 
def print_summary_table(updates_data: List[Dict[str, Any]]) -> None:
    """Sorts CVEs by severity and prints a formatted table."""
    if not updates_data:
        log_info("No security updates requiring analysis were found.")
        return

    log_info("Generating vulnerability summary table...")
    print("\n" + "=" * 80)
    print("Vulnerability Summary for Pending Security Updates")
    print("=" * 80)
    pkg_col, cve_col, score_col, sev_col, ver_col = 25, 18, 6, 10, 5
    total_width = pkg_col + cve_col + score_col + sev_col + ver_col + 10

    def severity_sort_key(cve_info: Dict[str, Any]) -> int:
        severity_str = cve_info.get('severity') or "UNKNOWN"
        return SEVERITY_ORDER.get(severity_str.upper(), 0)

    for package_data in updates_data:
        package, current_ver, new_ver, cves = (
            package_data['package'], package_data['current_version'],
            package_data['new_version'], package_data['cves']
        )
        print(f"\n--- Package: {package} ---")
        print(f"    Update: {current_ver} -> {new_ver}")
        if not cves:
            print("    No relevant CVEs found or processed for this update range.")
            continue

        cves.sort(key=severity_sort_key, reverse=True)
        print("-" * total_width)
        print(f"{'CVE ID':<{cve_col}} | {'Score':<{score_col}} | {'Severity':<{sev_col}} | {'CVSS':<{ver_col}}")
        print("-" * total_width)
        for cve_info in cves:
            cve_id = cve_info.get('id', 'N/A')
            score = cve_info.get('score')
            severity = cve_info.get('severity', 'N/A')
            cvss_ver = cve_info.get('version', 'N/A')
            score_str = f"{score:.1f}" if score is not None else "N/A"
            print(f"{cve_id:<{cve_col}} | {score_str:<{score_col}} | {severity:<{sev_col}} | {cvss_ver:<{ver_col}}")
        print("-" * total_width)
    print("\n" + "=" * 80)


# --- Main Execution --- 
def parse_upgradable_line(line: str) -> Optional[Tuple[str, str, str, str]]:
    """Parses a line from `apt list --upgradable`."""
    list_regex = re.compile(r"^([^/]+)/([^ ]+) ([^ ]+) ([^ ]+) \[upgradable from: ([^\]]+)\]")
    match = list_regex.match(line)
    if match:
        package, repo, new_version, _, old_version = match.groups()
        return package, repo, new_version, old_version
    else:
        list_regex_no_from = re.compile(r"^([^/]+)/([^ ]+) ([^ ]+) ([^ ]+).*")
        match_no_from = list_regex_no_from.match(line)
        if match_no_from:
             package, repo, new_version, _ = match_no_from.groups()
             return package, repo, new_version, ""
        if line and not line.startswith("Listing..."):
             log_warn(f"Could not parse line from 'apt list --upgradable': {line}")
        return None

def main() -> None:
    """Main script logic."""
    check_dependencies()
    ensure_root()
    update_package_lists()

    log_info("Checking for upgradable packages...")
    try:
        result = subprocess.run([APT_COMMAND, "list", "--upgradable"],
                                capture_output=True, text=True, check=True)
        upgradable_output = result.stdout
    except FileNotFoundError:
         fail(f"'{APT_COMMAND}' command not found.")
    except subprocess.CalledProcessError as e:
        fail(f"'{APT_COMMAND} list --upgradable' failed:\n{e.stderr}")
    except Exception as e:
        fail(f"An unexpected error occurred running apt list: {e}")

    if not upgradable_output.strip() or len(upgradable_output.splitlines()) <= 1:
        log_info("No packages found that need upgrading.")
        sys.exit(0)

    log_info("Collecting data for security updates...")
    all_updates_data: List[Dict[str, Any]] = []
    security_updates_processed_count: int = 0

    for line in upgradable_output.splitlines()[1:]:
        if not line.strip(): continue
        parsed_info = parse_upgradable_line(line)
        if not parsed_info: continue
        package, repo, new_version, old_version = parsed_info

        if "-security" in repo:
            log_info(f"Processing security package: {package} ({old_version} -> {new_version})")
            security_updates_processed_count += 1
            if not old_version:
                log_warn(f"Skipping {package}: Could not determine current version.")
                continue

            current_package_data: Dict[str, Any] = {
                "package": package, "current_version": old_version,
                "new_version": new_version, "cves": []
            }
            cve_ids = find_cves_in_changelog_range(package, old_version, new_version)

            if cve_ids:
                log_info(f"Processing {len(cve_ids)} potential CVEs for {package}...")
                api_call_made_in_batch = False # Track if we hit the API in this batch
                for cve_id in cve_ids:
                    clean_cve_id = cve_id.strip()
                    if not clean_cve_id: continue

                    # Check cache *before* deciding if an API call might be needed
                    was_cached = clean_cve_id in CVE_SCORE_CACHE

                    score, severity, cvss_ver = get_cvss_score(clean_cve_id)

                    # Decide if an API call was likely made (i.e., it wasn't cached initially)
                    if not was_cached:
                        api_call_made_in_batch = True

                    cve_info = {"id": clean_cve_id, "score": score, "severity": severity, "version": cvss_ver}
                    current_package_data["cves"].append(cve_info)

                    # Sleep *only if* an API call was potentially made for this CVE
                    if not was_cached:
                        time.sleep(NVD_API_DELAY_SECONDS)

            all_updates_data.append(current_package_data)
        # End if "-security" in repo
    # End loop through upgradable packages

    print_summary_table(all_updates_data)

    if security_updates_processed_count == 0:
         log_info("No pending updates identified from security repositories.")
    else:
        log_info(f"Processed {security_updates_processed_count} potential security update(s).")
    log_info("Script finished.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(130)