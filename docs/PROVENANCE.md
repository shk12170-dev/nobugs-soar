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
