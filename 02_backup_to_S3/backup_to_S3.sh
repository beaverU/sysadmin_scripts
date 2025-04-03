#!/bin/bash

VERBOSE=false
DRY_RUN=false
DEV_PATH=""
S3_LINK=""
RED=""

# syslog logging func
log_message() {
  local message=$1
  local priority=$2
  logger -p "user.$priority" -t "backup_to_S3.sh" "$message"
  if $VERBOSE; then
    echo "[$priority] $message"
  fi
}

# Checking script's args and validating input data
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
        if [[ -b "$OPTARG" ]] && echo "$OPTARG" | grep "^/dev/*" > /dev/null; then
          DEV_PATH=$OPTARG
        else
          echo "Check -p option. It isn't a block special file nor starts from '/dev/..'" "err"
          exit 1
        fi
        ;;
      s)
        if echo "$OPTARG" | grep "^s3://" > /dev/null; then 
          S3_LINK=$OPTARG
        else
          echo "Check -s option. Looks like the link isn't valid and doesn't start from 's3://'"
          exit 1
        fi
        ;;
      *)
        help_info
        ;;
    esac
  done
}

help_info() {
  echo "Usage: $0 -p String (LV partition to backup) -s String (S3 link to connect)"
  echo "        [ -v -- Verbose mode]"
  echo "        [ -d -- Dry run ]"
  exit 1
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
      log_message "Some problem has occur during snapshot creation " "error"
      exit 1
    else
      log_message "Snapshot has been made succesfully"
    fi
  fi
}

# Making an tar.gz archive from LVM snapshot
create_archive() {
  if $DRY_RUN; then
    echo "Making tar.gz archive"
    echo "tar -czf /backup/snapshot_backup.tar.gz /mnt/snapshot"
  else
    tar -czf /backup/snapshot_backup.tar.gz /mnt/snapshot
  fi
}

# Sending archive to S3 bucket
upload_to_s3() {
  if $DRY_RUN; then
    echo "Sending backup to S3 $S3_LINK" 
    echo "aws s3 cp /backup/snapshot_backup.tar.gz s3://mybucket/"
  else
    aws s3 cp /backup/snapshot_backup.tar.gz s3://mybucket/
  fi
}

main() {
  args_setup "$@"
  if [[ -z "$DEV_PATH" || -z "$S3_LINK" ]] ; then
    help_info
  fi
  flush_cache
  create_snapshot
  create_archive
  upload_to_s3
}

main "$@"