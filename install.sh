#!/bin/bash

# Установка Fail2Ban
sudo apt update && sudo apt install -y fail2ban
FAIL2BAN_STATUS=$?

# Создание действия iptables-ufw, если отсутствует
if [ ! -f /etc/fail2ban/action.d/iptables-ufw.conf ]; then
  sudo tee /etc/fail2ban/action.d/iptables-ufw.conf > /dev/null <<'EOF'
[Definition]
actionstart = ufw allow <port>
actionstop = ufw delete allow <port>
actioncheck = ufw status | grep -q '<port>'
actionban = ufw deny from <ip> to any port <port>
actionunban = ufw delete deny from <ip> to any port <port>
EOF
fi

# Получение порта x-ui
XUI_PORT=$(sudo ss -ntpl | grep 'x-ui' | grep -oP ':(\d+)' | tr -d ':')

# Настройка Fail2Ban для x-ui
sudo bash -c "cat > /etc/fail2ban/jail.d/x-ui.conf" <<EOF
[x-ui]
enabled = true
filter = x-ui
port = $XUI_PORT
backend = systemd
journalmatch = _SYSTEMD_UNIT=x-ui.service
findtime = 600
bantime = 3600
maxretry = 3
polltime = 1
banaction = iptables-ufw
action = %(action_)s
EOF

# Отключаем jail для sshd
echo -e '[sshd]\nenabled = false' | sudo tee /etc/fail2ban/jail.d/sshd.local > /dev/null

# Создаём фильтр для x-ui
sudo tee /etc/fail2ban/filter.d/x-ui.conf > /dev/null <<EOF
[Definition]
failregex = ^.*wrong username: .* IP: "<HOST>".*$
ignoreregex =
EOF

# Перезапуск Fail2Ban
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
