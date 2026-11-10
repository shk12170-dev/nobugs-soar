#!/bin/sh
# 매니저 주소를 ossec.conf에 반영하고, 웹 루트(S7 대상)를 실시간 FIM에 등록한 뒤,
# 등록 키가 없으면 agent-auth로 자동 등록(매니저의 authd, 1515)하고 에이전트를 시작한다.
set -e

sed -i "s#<address>.*</address>#<address>${WAZUH_MANAGER:-wazuh-manager}</address>#" /var/ossec/etc/ossec.conf

WEB_ROOT=${NB_WEB_ROOT:-/nobugs/web-root}
mkdir -p "$WEB_ROOT"
if ! grep -q ">$WEB_ROOT<" /var/ossec/etc/ossec.conf; then
  sed -i "0,/<syscheck>/s##<syscheck>\n    <directories realtime=\"yes\" check_all=\"yes\" report_changes=\"no\">$WEB_ROOT</directories>#" \
    /var/ossec/etc/ossec.conf
fi
# 바인드 마운트에서는 하위 폴더 실시간 감시가 빠질 수 있어 따로 등록한다.
if ! grep -q ">$WEB_ROOT/assets<" /var/ossec/etc/ossec.conf; then
  sed -i "0,/<syscheck>/s##<syscheck>\n    <directories realtime=\"yes\" check_all=\"yes\" report_changes=\"no\">$WEB_ROOT/assets</directories>#" \
    /var/ossec/etc/ossec.conf
fi
# 보완: 정기 스캔 주기를 짧게(실시간을 놓쳐도 늦어도 이 안에 잡도록). 기본 12시간 -> 20초.
sed -i "/<syscheck>/,/<\/syscheck>/ s#<frequency>[0-9]*</frequency>#<frequency>20</frequency>#" /var/ossec/etc/ossec.conf

if [ ! -s /var/ossec/etc/client.keys ]; then
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER:-wazuh-manager}" -A "${NB_AGENT_NAME:-nobugs-portal}" && break
    sleep 3
  done
fi

/var/ossec/bin/wazuh-control start
exec tail -F /var/ossec/logs/ossec.log
