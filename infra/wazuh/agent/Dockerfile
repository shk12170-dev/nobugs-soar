# S7(홈페이지 변조) 탐지용 FIM 전용 에이전트. 공식 wazuh-agent 이미지는 없어 매니저와 같은 버전의 deb를 직접 받는다.
# 능동 대응(Active Response)은 여기서 하지 않는다 — 탐지만 매니저로 보내고, 실제 복구는
# Graylog 집계 -> nobugs_engine 웹훅 -> 포털 대응 API 경로로 한다(이 저장소의 설계).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
ARG WAZUH_VERSION=4.9.0
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -fsSL -o /tmp/wa.deb "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_amd64.deb" \
 && WAZUH_MANAGER=wazuh-manager apt-get install -y /tmp/wa.deb && rm -f /tmp/wa.deb && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
