#!/bin/bash

VERBOSE=false
TMP_FILE="/tmp/sec.cache"

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

# Security updates check function
check_security_updates() {
  apt-get -s upgrade 2>/dev/null | grep -i security | grep -i Inst | cut -d ' ' -f 2 > "$TMP_FILE"
  if (( PIPESTATUS[0] != 0 )); then
    log_message "apt command has failed" "error"
    "$VERBOSE" && echo "apt command has failed."
    exit 1
  elif [[ -z "$(cat $TMP_FILE)" ]]; then
    log_message "All security updates are installed." "info"
    "$VERBOSE" && echo "All security updates are installed."
  else
    log_message "Security updates has found." "warning"
    "$VERBOSE" && echo "Security updates has found."
  fi
}

# Checking script's args
args_setup() {
  while getopts "vh" opt; do
    case $opt in
      v) VERBOSE=true; echo "Verbose mode on" ;;
      *) echo "Usage: $0 [-v]"; exit 1 ;;
    esac
  done
}

main() {

  trap cleanup EXIT

  args_setup "$@"
  
  check_security_updates
  
}

main "$@"
