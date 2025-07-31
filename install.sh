#!/bin/bash

# Установка Fail2Ban
sudo apt update && sudo apt install -y fail2ban
FAIL2BAN_STATUS=$?

# Получение порта x-ui
XUI_PORT=$(sudo ss -ntpl | grep 'x-ui' | grep -oP ':(\d+)' | tr -d ':')

# Настройка Fail2Ban для x-ui
XUI_PORT=$(sudo ss -ntpl | grep 'x-ui' | grep -oP ':(\d+)' | tr -d ':')

sudo bash -c "echo -e '[x-ui]
enabled = true
filter = x-ui
port = $XUI_PORT
backend = systemd
journalmatch = _SYSTEMD_UNIT=x-ui.service
findtime = 60
bantime = 3600
maxretry = 3
banaction = iptables-xui' > /etc/fail2ban/jail.d/x-ui.conf"

echo -e '[sshd]\nenabled = false' | sudo tee /etc/fail2ban/jail.d/sshd.local > /dev/null

echo -e '[Definition]\nfailregex = ^.*wrong username: .* IP: "<HOST>".*$\nignoreregex =' | sudo tee /etc/fail2ban/filter.d/x-ui.conf > /dev/null

sudo tee /etc/fail2ban/action.d/iptables-xui.conf > /dev/null <<EOF
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = iptables -I INPUT -p tcp --dport <port> -s <ip> -j REJECT --reject-with icmp-port-unreachable
actionunban = iptables -D INPUT -p tcp --dport <port> -s <ip> -j REJECT --reject-with icmp-port-unreachable
EOF

sudo systemctl restart fail2ban

# Имитируем ложную попытку входа в журнал systemd
logger --journald <<EOF
PRIORITY=4
SYSLOG_IDENTIFIER=x-ui
MESSAGE=WARNING - wrong username: "fail2ban_test", password: "invalid", IP: "127.0.0.2"
EOF

# Даём время fail2ban распарсить запись
sleep 3

# Проверка работы Fail2Ban
F2B_ACTIVE=$(sudo systemctl is-active fail2ban)
SSH_DISABLED=$(grep -q 'enabled = false' /etc/fail2ban/jail.d/sshd.local && echo true || echo false)
XUI_JAIL_EXISTS=$(sudo fail2ban-client status x-ui &> /dev/null && echo true || echo false)

# Установка и настройка CrowdSec
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
sudo apt install -y crowdsec
sudo apt update
sudo apt install -y crowdsec-firewall-bouncer-iptables
sudo sed -i 's/mode: iptables/mode: nftables/' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
sudo systemctl restart crowdsec
sudo systemctl restart crowdsec-firewall-bouncer

# Проверка компонентов CrowdSec
CROWDSEC_STATUS=$(sudo systemctl is-active crowdsec)
BOUNCER_STATUS=$(sudo cscli bouncers list | grep -q '✔️' && echo OK || echo FAIL)
SSH_BF_ENABLED=$(sudo cscli scenarios list | grep -q 'ssh-bf' && echo OK || echo FAIL)

# Добавление и проверка тестовой блокировки
sudo cscli decisions add --ip 1.2.3.4 --reason "test" --duration 10m
sleep 2
DECISION_ACTIVE=$(sudo cscli decisions list | grep -q '1.2.3.4' && echo OK || echo FAIL)

# Финальный отчет
echo -e "\n===== ОТЧЕТ О НАСТРОЙКЕ ====="
echo -e "🔧 Fail2Ban установлен:          [$([ $FAIL2BAN_STATUS -eq 0 ] && echo OK || echo FAIL)]"
echo -e "🛡  Fail2Ban активен:             [$([ "$F2B_ACTIVE" == "active" ] && echo OK || echo FAIL)]"
echo -e "🔒 SSH мониторинг отключён:      [$([ "$SSH_DISABLED" == "true" ] && echo OK || echo FAIL)]"
echo -e "🛡  Защита x-ui активна (порт $XUI_PORT): [$([ "$XUI_JAIL_EXISTS" == "true" ] && echo OK || echo FAIL)]"
echo -e "📦 CrowdSec установлен:          [$([ "$CROWDSEC_STATUS" == "active" ] && echo OK || echo FAIL)]"
echo -e "🚧 Bouncer подключен:            [$BOUNCER_STATUS]"
echo -e "📜 Сценарий ssh-bf активен:      [$SSH_BF_ENABLED]"
echo -e "🔎 Тестовая блокировка активна: [$DECISION_ACTIVE]"
echo -e "==============================="
