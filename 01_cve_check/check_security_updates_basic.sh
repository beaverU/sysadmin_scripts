#!/bin/bash

# Checks for Ubuntu/Debian security updates, identifies packages that
# need to be upgraded

VERBOSE=false

# syslog logging func
log_message() {
  local message=$1
  local priority=$2
  logger -p "user.$priority" -t "check_security_updates_basic.sh" "$message"
  if $VERBOSE; then
    echo "[$priority] $message"
  fi
}

# Checking script's args
args_setup() {
  while getopts ":v" opt; do
    case $opt in
      v) VERBOSE=true; echo "Verbose mode on" ;;
      *) echo "Usage: $0 [-v]"; exit 1 ;;
    esac
  done
}

# Checks if required commands are available in PATH.
check_dependencies() {
  local dep
  for dep in apt-get grep logger; do
    if ! command -v "${dep}" >/dev/null 2>&1; then
      log_message "'${dep}' is required but not installed. Please install it." "err"
    fi
  done
  if ! command -v apt >/dev/null 2>&1; then
      log_message "'apt' command not found. Is this an APT-based system (Debian/Ubuntu)?" "err"
  fi
}

# Security updates check function
check_security_updates() {
  local updates
  updates=$(apt-get -s upgrade 2>/dev/null | grep -i security | grep -i Inst| cut -d ' ' -f 2-4 | sed 's/(//g')
  if [[ -z "$updates" ]]; then
    log_message "All security updates are installed." "info"
  else
    log_message "Security updates has found. $updates" "warning"
  fi
}

main() {

  args_setup "$@"

  check_dependencies
  
  check_security_updates
  
}

main "$@"
