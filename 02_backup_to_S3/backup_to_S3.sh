#!/bin/bash

VERBOSE=false
DRY_RUN=false
DEV_PATH="None"
S3_LINK="None"

# syslog logging func
log_message() {
  local message=$1
  local priority=$2
  logger -p "user.$priority" -t "backup_to_S3.sh" "$message"
  if $VERBOSE; then
    echo "[$priority] $message"
  fi
}

# Checking script's args
args_setup() {
  while getopts ":vdp:s:" opt; do
    case "${opt}" in
      v)
        VERBOSE=true
        echo "Verbose mode on" 
        ;;
      d)
        DRY_RUN=true
        echo "Dry run mode on. Comands won't be executed, so you can check that script is running as it suppose to."
        ;;
      p) 
        DEV_PATH=$OPTARG
        while [ -z "$$OPTARG" ]; do
          read -p "Enter path to the logical volume. e.g. /dev/vg_some/lvol0\n Type: " DEV_PATH
        done
        ;;
      s)
        S3_LINK=$OPTARG
        ;;
      *)
        echo "Invalid option"
        echo "Usage: $0 [-v|-d=LV partition to backup|-s=s3 link to connect]"
        exit 1
        ;;
    esac
  done
}

# VM cache flushing
flush_cache() {
  if $DRY_RUN; then
    echo "Flushing cache to the disk"
    echo "sync && echo 3 > /proc/sys/vm/drop_caches"
  else
    if ! sync && echo 3 > /proc/sys/vm/drop_caches; then
      log_message "Couldn't flush cache" "err"
      exit 1
    else
      log_message "Cache has been flushed" "info"
    fi
  fi
}

# LVM snapshot creation
create_snapshot() {
  if $DRY_RUN; then
    echo "Creating lvm snapshot"
    echo "lvcreate --size 1G --snapshot --name backup_snapshot " "$DEV_PATH"
  else
    if ! lvcreate --size 1G --snapshot --name backup_snapshot $$DEV_PATH; then
      log_message "Some problem has occur during creating snapshot" "error"
      exit 1
    else
      log_message "Snapshot has been made succesfully"
    fi
  fi
}

# Making an tar.gz archive from LVM snapshot
create_archive() {
  tar -czf /backup/snapshot_backup.tar.gz /mnt/snapshot
}

# Sending archive to S3 bucket
upload_to_s3() {
  aws s3 cp /backup/snapshot_backup.tar.gz s3://mybucket/
}

main() {
  args_setup "$@"
  if [ -e "$DEV_PATH" ] && echo "$S3_LINK" | grep "^s3://" ; then
    log_message "Placeholder" "info"
  else
    log_message "Couldn't find valid partition file or s3 link. Check -p and -s options" "err"
    exit 1
  fi
  flush_cache
  create_snapshot
  create_archive
  upload_to_s3
}

main "$@"