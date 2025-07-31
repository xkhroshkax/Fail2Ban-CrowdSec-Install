#!/bin/bash

# Установка необходимых пакетов
sudo apt update && sudo apt install -y fail2ban jq
FAIL2BAN_STATUS=$?

# Получение порта x-ui
XUI_PORT=$(sudo ss -ntpl | grep 'x-ui' | grep -oP ':(\d+)' | tr -d ':' | head -1)
if [ -z "$XUI_PORT" ]; then
  XUI_PORT=$(jq -r '.port' /root/3x-ui/config.json 2>/dev/null)
  if [ -z "$XUI_PORT" ] || [ "$XUI_PORT" = "null" ]; then
    XUI_PORT=54321
    echo "Порт x-ui не найден, используется порт по умолчанию: $XUI_PORT"
  else
    echo "Порт x-ui найден в config.json: $XUI_PORT"
  fi
else
  echo "Порт x-ui найден через ss: $XUI_PORT"
fi

# Проверка и создание лог-файла x-ui
XUI_LOG="/root/3x-ui/access.log"
if [ ! -f "$XUI_LOG" ]; then
  sudo touch "$XUI_LOG"
  sudo chown x-ui:x-ui "$XUI_LOG" 2>/dev/null || sudo chown root:root "$XUI_LOG"
  sudo chmod 640 "$XUI_LOG"
  echo "Лог-файл x-ui создан: $XUI_LOG"
fi

# Настройка Fail2Ban для x-ui
sudo tee /etc/fail2ban/jail.d/x-ui.conf > /dev/null << EOF
[x-ui]
enabled = true
filter = x-ui
port = $XUI_PORT
logpath = $XUI_LOG
backend = polling
findtime = 600
bantime = 3600
maxretry = 3
action = iptables-multiport[name=x-ui, port="$XUI_PORT", protocol=tcp]
EOF

# Отключение SSH мониторинга
echo -e '[sshd]\nenabled = false' | sudo tee /etc/fail2ban/jail.d/sshd.local > /dev/null

# Настройка фильтра для x-ui
sudo tee /etc/fail2ban/filter.d/x-ui.conf > /dev/null << 'EOF'
[Definition]
failregex = ^.*"POST /xui/login HTTP/[0-1]\.[0-1]" 401.*$
            ^.*"POST /panel/login HTTP/[0-1]\.[0-1]" 401.*$
            ^.*failed login attempt.*$
ignoreregex =
EOF

# Перезапуск Fail2Ban
sudo systemctl restart fail2ban
sleep 2

# Проверка работы Fail2Ban
F2B_ACTIVE=$(sudo systemctl is-active fail2ban)
SSH_DISABLED=$(grep -q 'enabled = false' /etc/fail2ban/jail.d/sshd.local && echo true || echo false)
XUI_JAIL_EXISTS=$(sudo fail2ban-client status x-ui &> /dev/null && echo true || echo false)

# Установка и настройка CrowdSec
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
sudo apt install -y crowdsec
sudo apt update
sudo apt install -y crowdsec-firewall-bouncer-iptables

# Настройка парсера логов x-ui для CrowdSec
sudo mkdir -p /etc/crowdsec/parsers/s02-enrich
sudo tee /etc/crowdsec/parsers/s02-enrich/x-ui.yaml > /dev/null << EOF
name: custom/x-ui
description: "Parser for x-ui login attempts"
filter: "evt.Line.Module == 'file' && evt.Line.Src == '$XUI_LOG'"
onsuccess: next_stage
grok:
  pattern: ^.*"POST /(xui|panel)/login HTTP/[0-1]\.[0-1]" 401.*$
  apply_on: Line.Raw
  statics:
    - meta: log_type
      value: x-ui_failed_login
EOF

# Настройка сценария для x-ui в CrowdSec
sudo mkdir -p /etc/crowdsec/scenarios
sudo tee /etc/crowdsec/scenarios/x-ui-bf.yaml > /dev/null << 'EOF'
type: leaky
name: custom/x-ui-bf
description: "Detect brute force attacks on x-ui panel"
filter: "evt.Meta.log_type == 'x-ui_failed_login'"
groupby: evt.Meta.source_ip
capacity: 3
leakage: 600
duration: 3600
blackhole: 1h
EOF

# Регистрация парсера и сценария
sudo cscli parsers install /etc/crowdsec/parsers/s02-enrich/x-ui.yaml
sudo cscli scenarios install /etc/crowdsec/scenarios/x-ui-bf.yaml

# Настройка bouncer
sudo sed -i 's/mode: iptables/mode: nftables/' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml 2>/dev/null || true
sudo systemctl restart crowdsec
sudo systemctl restart crowdsec-firewall-bouncer

# Добавление источника логов в CrowdSec
sudo tee /etc/crowdsec/acquis.yaml > /dev/null << EOF
filenames:
  - $XUI_LOG
labels:
  type: x-ui
EOF

# Проверка компонентов CrowdSec
CROWDSEC_STATUS=$(sudo systemctl is-active crowdsec)
BOUNCER_STATUS=$(sudo cscli bouncers list | grep -q '✔️' && echo OK || echo FAIL)
SSH_BF_ENABLED=$(sudo cscli scenarios list | grep -q 'ssh-bf' && echo OK || echo FAIL)
XUI_BF_ENABLED=$(sudo cscli scenarios list | grep -q 'x-ui-bf' && echo OK || echo FAIL)

# Добавление и проверка тестовой блокировки
sudo cscli decisions add --ip 1.2.3.4 --reason "test" --duration 10m
sleep 2
DECISION_ACTIVE=$(sudo cscli decisions list | grep -q '1.2.3.4' && echo OK || echo FAIL)

# Финальный отчет
echo -e "\n===== ОТЧЕТ О НАСТРОЙКЕ ====="
echo -e "🔧 Fail2Ban установлен:          [$([ $FAIL2BAN_STATUS -eq 0 ] && echo OK || echo FAIL)]"
echo -e "🛡  Fail2Ban активен:             [$([ \"$F2B_ACTIVE\" == \"active\" ] && echo OK || echo FAIL)]"
echo -e "🔒 SSH мониторинг отключён:      [$([ \"$SSH_DISABLED\" == \"true\" ] && echo OK || echo FAIL)]"
echo -e "🛡  Защита x-ui активна (порт $XUI_PORT): [$([ \"$XUI_JAIL_EXISTS\" == \"true\" ] && echo OK || echo FAIL)]"
echo -e "📦 CrowdSec установлен:          [$([ \"$CROWDSEC_STATUS\" == \"active\" ] && echo OK || echo FAIL)]"
echo -e "🚧 Bouncer подключен:            [$BOUNCER_STATUS]"
echo -e "📜 Сценарий ssh-bf активен:      [$SSH_BF_ENABLED]"
echo -e "📜 Сценарий x-ui-bf активен:     [$XUI_BF_ENABLED]"
echo -e "🔎 Тестовая блокировка активна: [$DECISION_ACTIVE]"
echo -e "==============================="
