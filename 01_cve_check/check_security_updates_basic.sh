#!/bin/bash

# syslog logging func
log_message() {
  local message=$1
  local priority=$2
  logger -p "$priority" "$message"
}

# Security updates check function
check_security_updates() {
  updates=$(apt list --upgradable 2>/dev/null | grep -i security)
  
  if [[ -z "$updates" ]]; then
    log_message "All security updates are installed." "info"
  else
    log_message "Security updates has found." "warning"
  fi
}

main() {
  if ! check_security_updates; then
    echo "There is an error"
    exit 1
  fi
}

main $@
