#!/bin/bash
while ping -c 1 google.com >/dev/null 2>&1; do
  echo "Google доступен"
  sleep 1
done
  echo "Google недоступен"
