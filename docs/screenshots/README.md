# 스크린샷 모음

실제 구동 화면 캡처(2026-11-11, 이 PC에서 전부 로컬로 띄운 상태). 발표·포트폴리오용이다. 전체 구조는
[docs/ARCHITECTURE.md](../ARCHITECTURE.md), 측정 수치는 [docs/MEASUREMENTS.md](../MEASUREMENTS.md)를 본다.

| 파일 | 화면 | 무엇을 보여주나 |
| --- | --- | --- |
| [01-control-panel.jpg](01-control-panel.jpg) | 실습 제어판(5102) | 티켓마다 **공격→탐지→조치→반영 확인→효과 확인→원복** 6단계. S8·S1·S10이 대부분 restored/closed |
| [02-engine-tickets.jpg](02-engine-tickets.jpg) | 대응 엔진(5200) | S1·S4·S7·S8·S10·S12 전 케이스의 티켓 목록과 상태(restored·verified·closed) |
| [03-portal.jpg](03-portal.jpg) | 민원 포털(5100) | 시민 민원 포털 첫 화면(이벤트 발생원) |
| [04-graylog-filterlog.jpg](04-graylog-filterlog.jpg) | Graylog(9100) | `filterlog` 검색 59건, source `172.16.50.2` — pfSense 방화벽 로그가 중계기를 거쳐 수집됨 |
| [05-demo-s8-cycle.gif](05-demo-s8-cycle.gif) | 실습 제어판(5102), 움직이는 그림 | **S8 한 사이클**: 평상시 → 공격 → 탐지 → 차단·반영·효과 확인(①~⑤) → 자동 원복(⑥ `restored`). 2026-11-13 실제 스택으로 녹화(시연용 TTL 30초), 장면마다 자막 |

## 캡처 메모

- 01~03은 내장 브라우저(127.0.0.1)에서, 04는 로그인돼 있던 브라우저의 Graylog 화면에서 캡처했다.
- 01의 제어판은 엔진(5200)의 실제 티켓을 읽어 그린다 — 화면의 티켓·상태는 합성이 아니라 실제 엔진 상태다.
- 04의 메시지 본문은 pfSense `filterlog` 원문(예: `...,match,block,...,172.16.50.x,...`)이며 source가
  `172.16.50.2`로 찍힌다(중계기가 GELF host를 보낸 IP로 채운 결과, [ARCHITECTURE.md](../ARCHITECTURE.md) 5절).

> 05는 Chrome에서 실제 사이클을 진행하며 저장한 화면 6장을 자막과 함께 GIF로 엮은 것이다(소리·내레이션 없음). 내레이션을 넣은 시연 영상은 [DEMO-SCRIPT.md](../DEMO-SCRIPT.md) 대본으로 따로 녹화한다.
