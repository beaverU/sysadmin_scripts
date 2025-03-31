#!/bin/bash
while ping -c 1 google.com >/dev/null 2>&1; do
  echo "Google is reachable"
  sleep 1
done
  echo "Google is unreachable"
