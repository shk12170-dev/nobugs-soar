# 코드 출처 기록

구현하면서 모듈마다 한 줄씩 추가합니다. 형식: `날짜 | 경로 | 출처(새로 작성 / 본인 이전 작성분 참고) | 메모`

| 날짜 | 경로 | 출처 | 메모 |
| --- | --- | --- | --- |
| 2026-11-09 | docs/ | 새로 작성 | 계획·명세. 동작 사실은 직접 시험 결과 기준 |
| 2026-11-10 | pyproject.toml, .github/, scripts/test.ps1 | 새로 작성 | M0 |
| 2026-11-10 | src/nobugs_portal/ (config, models, db, security, errors, netinfo, events, state, services, deps, app, control, routers/*) | 새로 작성 | M1. 명세(BEHAVIOR-SPEC)와 공식 문서만 참고. 팀 저장소 코드는 열어 보지 않고 작성 |
| 2026-11-10 | tests/ | 새로 작성 | 101건. 실제 서버 2개로 시험하다 찾은 결함 2건(동시 시작 시 표 생성 경쟁, 대응 앱 이벤트의 src_ip unknown)을 회귀 테스트로 고정 |
| 2026-11-10 | web/ (React+TS 화면, api.ts, 단위·E2E 테스트), src/nobugs_portal/web.py·cli.py, scripts/e2e_server.py | 새로 작성 | M2. 포털 이름은 가상 기관 "누리시청"으로 새로 정함 |
| 2026-11-10 | infra/docker-compose.yml, src/nobugs_tools/ (make_env, definitions, graylog, attacks), tests/test_tools.py | 새로 작성 | M3. Graylog 이벤트 정의 JSON 구조는 Graylog API 문서 기준으로 새로 작성. 테스트로 `env or` 빈 딕셔너리 결함 1건 발견·수정 |
| 2026-11-10 | src/nobugs_engine/ (config, models, store, portal, probe, notify, engine, app), src/nobugs_tools/ 확장(알림 연결), tests/test_engine*.py, tests/test_tools_notify.py | 새로 작성 | M4. 티켓 상태 기계는 본인 이전 작성분의 개념(단계·멱등·교착)을 참고했으나 코드는 새 설계(SQLAlchemy, 주입 시계, 같은 IP 일괄 원복) |
| 2026-11-10 | src/nobugs_boundary/ (경계 시뮬레이터), src/nobugs_engine/health.py, engine.py·portal.py·notify.py·app.py·config.py 확장(S4·S8·S10·S12), src/nobugs_portal/control.py 확장(account_state), src/nobugs_tools/definitions.py·attacks.py 확장, tests/test_engine_m5.py, tests/test_boundary_and_account_state.py, tests/test_tools.py 확장 | 새로 작성 | M5. 실제 서버(포털·대응 API·경계 시뮬레이터·엔진·Graylog)로 S4·S8→S10·S12를 각 1회 이상 완주 확인(아래 메모). 시험 중 Graylog 알림이 S8·S10 두 정의를 같은 트래픽에 동시에 발동시켜 `ip_block`이 중복 기록되는 경쟁 조건 1건을 실측으로 발견 → `Engine._lock`으로 엔진 판단·조치 구간을 직렬화해 수정, 회귀 테스트로 고정(`test_concurrent_s8_and_s10_detections_block_the_app_only_once`) |
