#!/bin/bash
#
# Checks for Ubuntu security updates, identifies CVEs fixed between the
# current and candidate versions, and retrieves their CVSS scores from NVD.

# --- Constants ---
readonly NVD_API_DELAY_SECONDS=2
readonly NVD_API_BASE_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"
readonly CURL_CONNECT_TIMEOUT_SECONDS=10
readonly CURL_MAX_TIME_SECONDS=25

# --- Logging Functions ---

# Prints an informational message to stdout.
# Arguments:
#   Message string
log_info() {
  echo "[INFO] $*"
}

# Prints a warning message to stderr.
# Arguments:
#   Message string
log_warn() {
  echo "[WARN] $*" >&2
}

# Prints an error message to stderr.
# Arguments:
#   Message string
log_error() {
  echo "[ERROR] $*" >&2
}

# Exits with an error message.
# Arguments:
#   Message string
fail() {
  log_error "$*"
  exit 1
}

# --- Helper Functions ---

# Checks if required commands are available in PATH.
check_dependencies() {
  local dep
  for dep in curl jq apt grep sort uniq head; do
    if ! command -v "${dep}" >/dev/null 2>&1; then
      fail "'${dep}' is required but not installed. Please install it."
    fi
  done
  if ! command -v apt >/dev/null 2>&1; then
      fail "'apt' command not found. Is this an APT-based system (Debian/Ubuntu)?"
  fi
}

# Ensures the script is running as root, re-executing with sudo if necessary.
ensure_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    log_info "Script needs root privileges for 'apt update'. Re-running with sudo..."
    # Attempt to re-execute with sudo, preserving arguments
    if ! exec sudo -n bash "$0" "$@"; then
       # Fallback if sudo -n fails (requires password)
       exec sudo bash "$0" "$@"
    fi
    # exec replaces the current process, script shouldn't continue here.
    # If exec fails (e.g., sudo not found), it will exit.
    fail "Failed to re-execute with sudo." # Should not be reached if exec succeeds
 fi
}

# Updates APT package lists.
update_package_lists() {
  log_info "Updating package lists..."
  if ! apt-get update -qq; then
    fail "Failed to update package lists. Check APT configuration and network."
  fi
  log_info "Package lists updated successfully."
}

# Fetches CVSS data for a given CVE from the NVD API.
# Arguments:
#   CVE identifier string (e.g., "CVE-2023-1234")
# Outputs:
#   On success: Prints formatted CVSS score lines (v3.1, v3.0, v2.0 fallback).
#   On failure: Prints warning messages to stderr. Returns non-zero status.
get_cvss_score() {
  local cve="${1}"
  local api_url
  local response
  local cvss_v3_1_score cvss_v3_1_severity
  local cvss_v3_0_score cvss_v3_0_severity
  local cvss_v2_score cvss_v2_severity
  local score_found=0

  api_url="${NVD_API_BASE_URL}?cveId=${cve}"
  log_info "      Querying NVD for ${cve} CVSS score..."

  # Fetch data from NVD API. -f makes curl fail silently on server errors (4xx, 5xx).
  # -sS shows errors if curl itself fails (network, timeout) but stays silent on success.
  response=$(curl --connect-timeout "${CURL_CONNECT_TIMEOUT_SECONDS}" \
                --max-time "${CURL_MAX_TIME_SECONDS}" \
                --location -fsS "${api_url}")
  # Check curl exit status explicitly
  if [[ $? -ne 0 ]]; then
      log_warn "      Failed to fetch data from NVD for ${cve}. Curl error."
      return 1
  fi

  # Basic check if the response looks like valid JSON and contains results
  if ! echo "${response}" | jq empty 2>/dev/null || \
     [[ "$(echo "${response}" | jq '.totalResults // 0')" -eq 0 ]]; then
    log_warn "      CVE ${cve} not found in NVD or failed to parse response."
    return 1
  fi

  # Extract scores using jq. Default to "N/A" if path doesn't exist.
  # Use temporary variables to check existence before printing.
  cvss_v3_1_score=$(echo "${response}" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore // "N/A"')
  cvss_v3_1_severity=$(echo "${response}" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // "N/A"')
  cvss_v3_0_score=$(echo "${response}" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV30[0].cvssData.baseScore // "N/A"')
  cvss_v3_0_severity=$(echo "${response}" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV30[0].cvssData.baseSeverity // "N/A"')
  cvss_v2_score=$(echo "${response}" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV2[0].cvssData.baseScore // "N/A"')
  cvss_v2_severity=$(echo "${response}" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV2[0].baseSeverity // "N/A"') # Official v2 severity

  # Display best available score
  if [[ "${cvss_v3_1_score}" != "N/A" ]]; then
    echo "        CVSS v3.1: ${cvss_v3_1_score} (${cvss_v3_1_severity})"
    score_found=1
  elif [[ "${cvss_v3_0_score}" != "N/A" ]]; then
    echo "        CVSS v3.0: ${cvss_v3_0_score} (${cvss_v3_0_severity})"
    score_found=1
  elif [[ "${cvss_v2_score}" != "N/A" ]]; then
    if [[ "${cvss_v2_severity}" != "N/A" ]]; then
        echo "        CVSS v2.0: ${cvss_v2_score} (${cvss_v2_severity})"
    else
        echo "        CVSS v2.0: ${cvss_v2_score}"
    fi
    score_found=1
  fi

  if [[ "${score_found}" -eq 0 ]]; then
     log_warn "      No CVSS score (v3.x or v2.0) found in NVD data for ${cve}."
     return 1 # Indicate score wasn't found/displayed
  fi

  return 0 # Success
}


# Parses changelog to find CVEs between two versions.
# Arguments:
#   Package name
#   Current (old) version string
#   Candidate (new) version string
# Outputs:
#   Prints unique CVE identifiers found in the range, one per line, to stdout.
#   Prints status messages to stderr. Returns non-zero on failure.
find_cves_in_changelog_range() {
  local package="${1}"
  local old_version="${2}"
  local new_version="${3}"
  local changelog
  local -A cves_in_range_map # Associative array for unique CVEs (Bash 4+)
  local collecting_cves=0 # Flag: 0 = no, 1 = yes
  local clog_line entry_version version_regex found_cve

  log_info "  Fetching changelog for ${package}..." >&2
  changelog=$(apt-get changelog "${package}" 2>/dev/null)
  if [[ $? -ne 0 ]] || [[ -z "${changelog}" ]]; then
    log_warn "  Could not fetch or changelog empty for ${package}."
    return 1
  fi

  # Regex to capture version from lines like: pkg (version) dist; urgency=...
  version_regex="^\S+ \(([^)]+)\) .*"

  # Read the changelog line by line
  while IFS= read -r clog_line; do
    if [[ "${clog_line}" =~ ${version_regex} ]]; then
      entry_version="${BASH_REMATCH[1]}"

      # Compare versions exactly
      if [[ "${entry_version}" == "${new_version}" ]]; then
        log_info "    (Changelog: Found entry for new version ${new_version}, starting CVE collection)" >&2
        collecting_cves=1
      elif [[ "${entry_version}" == "${old_version}" ]]; then
        log_info "    (Changelog: Found entry for current version ${old_version}, stopping CVE collection)" >&2
        collecting_cves=0
        break # Stop reading changelog
      fi
    fi

    # If in collection mode, find CVEs on the current line
    if [[ "${collecting_cves}" -eq 1 ]]; then
      # Use process substitution with grep -oE to find all CVEs on the line
      while IFS= read -r found_cve; do
        # Check if grep actually found something (non-empty)
        if [[ -n "${found_cve}" ]]; then
          cves_in_range_map["${found_cve}"]=1 # Add to map for uniqueness
        fi
      done < <(grep -oE 'CVE-[0-9]{4}-[0-9]+' <<< "${clog_line}")
    fi
  done <<< "${changelog}" # Feed changelog to the loop

  # Check if any CVEs were found
  if [[ ${#cves_in_range_map[@]} -gt 0 ]]; then
      # Print unique CVEs (keys of the map), sorted
      printf "%s\n" "${!cves_in_range_map[@]}" | sort
      return 0
  else
      log_info "  No specific CVE identifiers found in changelog between versions ${old_version} and ${new_version}." >&2
      return 1 # Indicate no CVEs found
  fi
}


# --- Main Function ---
main() {
  # Exit on error, treat unset variables as errors, pipelines fail on first error
  #set -euo pipefail

  check_dependencies
  ensure_root "$@" # Re-executes with sudo if not already root

  update_package_lists

  log_info "Checking for upgradable packages..."
  # Get upgradable packages, skip header. Use apt-get for more stable output?
  # apt list output might be better for parsing repos... stick with apt list for now.
  local upgradable_output
  upgradable_output=$(apt list --upgradable 2>/dev/null | tail -n +2)

  if [[ -z "${upgradable_output}" ]]; then
    log_info "No packages found that need upgrading. System is up-to-date."
    exit 0
  fi

  log_info "Filtering for security updates, analyzing changelogs, and fetching CVSS..."
  local security_updates_found=0
  local line package repo new_version old_version
  local list_regex='^([^/]+)/([^ ]+) ([^ ]+) ([^ ]+) .*' # Grps: 1=pkg, 2=repo, 3=ver, 4=arch
  local from_regex='\[upgradable from: ([^]]+)\]'       # Grp: 1=old_ver

  # Process each line of the upgradable packages output
  while IFS= read -r line; do
    if [[ "${line}" =~ ${list_regex} ]]; then
      package="${BASH_REMATCH[1]}"
      repo="${BASH_REMATCH[2]}"
      new_version="${BASH_REMATCH[3]}"
      #arch="${BASH_REMATCH[4]}" # Not currently used

      # Check if it's likely a security update
      if [[ "${repo}" == *"-security"* ]]; then
        ((security_updates_found++))
        echo "--------------------------------------------------"
        log_info "Security Update Candidate:"
        echo "  Package:      ${package}"
        echo "  Repository:   ${repo}"
        echo "  New Version:  ${new_version}"

        # Extract the old version
        if [[ "${line}" =~ ${from_regex} ]]; then
          old_version="${BASH_REMATCH[1]}"
          echo "  Current Ver:  ${old_version}"
        else
          log_warn "  Could not determine current version for ${package}. Cannot accurately determine fixed CVEs."
          continue # Skip this package
        fi

        # Find CVEs fixed in this specific update range
        local cve_list cve
        # Use command substitution and check exit status
        if cve_list=$(find_cves_in_changelog_range "${package}" "${old_version}" "${new_version}"); then
           log_info "  Found unique CVE(s) potentially fixed:"

           # Process the list of CVEs returned by the function
           while IFS= read -r cve; do
              # Remove potential trailing carriage return before using the variable
              cve=${cve%$'\r'}
              # Now check if it's empty AFTER stripping \r
              [[ -z "${cve}" ]] && continue # Skip empty lines

              echo "    - ${cve}"
              # Call function to get and print CVSS scores
              get_cvss_score "${cve}" # Pass the cleaned CVE ID
              # Sleep required between API calls regardless of success
              sleep "${NVD_API_DELAY_SECONDS}"
           done <<< "${cve_list}"
        fi # End if CVEs found by find_cves_in_changelog_range
        # If find_cves_in_changelog_range returned non-zero, it already logged the reason.
      fi # End if repo contains "-security"
    else
      # Log lines that don't match the expected format
      if [[ -n "${line}" ]]; then # Avoid warning on empty lines
           log_warn "Could not parse line from 'apt list --upgradable': ${line}"
      fi
    fi # End if line matches list_regex
  done <<< "${upgradable_output}" # Feed upgradable list to the outer while loop

  echo "--------------------------------------------------"

  if [[ "${security_updates_found}" -eq 0 ]]; then
    log_info "No pending updates found specifically from a security repository."
    log_info "Note: Other available updates might still contain security fixes."
  else
    log_info "Found ${security_updates_found} potential security update(s) listed above."
  fi

  log_info "Script finished."
}

# --- Script Execution ---

# Call the main function, passing all script arguments
main "$@"