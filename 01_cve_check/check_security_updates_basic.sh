#!/bin/bash

# Функция логирования в syslog
log_message() {
  local message=$1
  local priority=$2
  logger -p "$priority" "$message"
}
# Функция проверки обновлений безопасности
check_security_updates() {
  # Проверяем наличие обновлений
  updates=$(apt list --upgradable 2>/dev/null | grep -i security)
  
  if [[ -z "$updates" ]]; then
    log_message "Все обновления безопасности установлены." "info"
  else
    # Здесь может быть код для оценки опасности уязвимостей по CVSS
    log_message "Найдены уязвимости, необходимо обновление." "warning"
  fi
}
main() {
  if ! check_security_updates; then
    echo "There is an error"
    exit 1
  fi
}
# Основная логика
main
