# nobugs-soar

공공기관 민원 포털을 공격 → **탐지(Graylog·Wazuh)** → **자동 대응(Python 대응 엔진)** → **차단·잠금·복구** → **티켓·효과 확인·자동 원복**까지 한 흐름으로 보여 주는 보안 관제·자동 대응(SOAR) 프로젝트입니다.

팀 캡스톤(NoBugs 1조, 2026.10~11)에서 다뤘던 문제를 **혼자, 처음부터 새로 설계·구현**하는 저장소입니다. 이전에 만든 재현판(`haedam-soar`, 비공개)과 달리 포털·대응 로직·탐지 규칙을 본인 코드로 새로 작성합니다. 출처·작성 규칙은 [docs/CLEANROOM.md](docs/CLEANROOM.md)에 있습니다.

## 상태

**M1 완료 — 포털 백엔드(FastAPI) + 별도 대응 API 앱.** 테스트 101건 통과, 실제 서버 프로세스 2개로 차단 시나리오를 확인했습니다. 프론트(M2)·관제 연결(M3)·대응 엔진(M4)은 아직입니다. 단계별 계획은 [docs/PLAN.md](docs/PLAN.md), 구현할 동작의 기준은 [docs/BEHAVIOR-SPEC.md](docs/BEHAVIOR-SPEC.md)입니다.

## 구성 (목표)

```
공격 스크립트 ─▶ 포털(FastAPI + React) ──GELF──▶ Graylog ──탐지 이벤트──▶ 대응 엔진(Python)
                     ▲                                  ▲                          │ 차단·잠금·복구
                     │                                  └── Wazuh(FIM) 경보 ───────┤
                     └──────── 차단 목록·세션 회수 ◀───────────────────────────────┤
                                                                   티켓 저장소·대시보드·알림 ◀┘
```

## 실행 (M1 시점: 포털 백엔드만)

```powershell
py -m venv .venv; .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
$env:NB_RESPONSE_API_KEY='<무작위 키>'; $env:NB_RESPONSE_ALLOWED_CIDRS='127.0.0.0/8'
.\.venv\Scripts\python.exe -m uvicorn nobugs_portal.app:public_factory --factory --port 5100 --app-dir src      # 일반 포털
.\.venv\Scripts\python.exe -m uvicorn nobugs_portal.control:control_factory --factory --port 5101 --app-dir src  # 대응 API(별도 프로세스)
.\scripts	est.ps1   # 린트 + 테스트
```

## 실행 (최종 목표)

`docker compose up -d` 와 설치 스크립트 한 번으로 전체가 뜨는 것이 최종 목표입니다(M7).

## 개발 방식

- 동작 명세와 테스트를 먼저 쓰고 구현합니다. 각 단계는 시연 가능한 결과로 끝납니다.
- AI 코딩 도구(Claude Code)를 보조로 사용합니다. 설계 결정과 검증은 본인이 합니다.
