#!/bin/bash

# Checks for Ubuntu/Debian security updates, identifies packages that
# need to be upgraded

VERBOSE=false

# syslog logging func
log_message() {
  local message=$1
  local priority=$2
  logger -p "$priority" "$message"
}

cleanup() {
  if [[ -e "$TMP_FILE" ]]; then
    rm /tmp/sec.cache
  fi
}

# Checking script's args
args_setup() {
  while getopts ":vh" opt; do
    case $opt in
      v) VERBOSE=true; echo "Verbose mode on" ;;
      *) echo "Usage: $0 [-v]"; exit 1 ;;
    esac
  done
}

# Security updates check function
check_security_updates() {
  local updates
  updates=$(apt-get -s upgrade 2>/dev/null | grep -i security | grep -i Inst| cut -d ' ' -f 2-4 | sed 's/(//g')
  if [[ -z "$updates" ]]; then
    log_message "All security updates are installed." "info"
    "$VERBOSE" && echo "All security updates are installed."
  else
    log_message "Security updates has found." "warning"
    "$VERBOSE" && echo "Security updates has found." && echo "$updates"
  fi
}

main() {

  trap cleanup EXIT

  args_setup "$@"
  
  check_security_updates
  
}

main "$@"
