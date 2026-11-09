# 코드 출처 기록

구현하면서 모듈마다 한 줄씩 추가합니다. 형식: `날짜 | 경로 | 출처(새로 작성 / 본인 이전 작성분 참고) | 메모`

| 날짜 | 경로 | 출처 | 메모 |
| --- | --- | --- | --- |
| 2026-11-09 | docs/ | 새로 작성 | 계획·명세. 동작 사실은 직접 시험 결과 기준 |
| 2026-11-10 | pyproject.toml, .github/, scripts/test.ps1 | 새로 작성 | M0 |
| 2026-11-10 | src/nobugs_portal/ (config, models, db, security, errors, netinfo, events, state, services, deps, app, control, routers/*) | 새로 작성 | M1. 명세(BEHAVIOR-SPEC)와 공식 문서만 참고. 팀 저장소 코드는 열어 보지 않고 작성 |
| 2026-11-10 | tests/ | 새로 작성 | 101건. 실제 서버 2개로 시험하다 찾은 결함 2건(동시 시작 시 표 생성 경쟁, 대응 앱 이벤트의 src_ip unknown)을 회귀 테스트로 고정 |
