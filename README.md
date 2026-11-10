# nobugs-soar

공공기관 민원 포털을 공격 → **탐지(Graylog·Wazuh)** → **자동 대응(Python 대응 엔진)** → **차단·잠금·복구** → **티켓·효과 확인·자동 원복**까지 한 흐름으로 보여 주는 보안 관제·자동 대응(SOAR) 프로젝트입니다.

팀 캡스톤(NoBugs 1조, 2026.10~11)에서 다뤘던 문제를 **혼자, 처음부터 새로 설계·구현**하는 저장소입니다. 이전에 만든 재현판(`haedam-soar`, 비공개)과 달리 포털·대응 로직·탐지 규칙을 본인 코드로 새로 작성합니다. 출처·작성 규칙은 [docs/CLEANROOM.md](docs/CLEANROOM.md)에 있습니다.

## 상태

**M5 완료 — S1·S4·S8·S10·S12 다섯 케이스가 탐지부터 자동(또는 사람) 원복까지 자동으로 돕니다.** 파이썬 테스트 266건, 프론트 단위 23건, 브라우저 E2E 7건이 통과합니다.

실제 시험(2026-11-10, Graylog·포털·대응 엔진·경계 시뮬레이터를 실제로 띄워 확인):
- **S1**: 공격 후 10초 만에 차단·효과 확인, TTL 30초 뒤 자동 원복, 같은 IP의 티켓 2개도 교착 없이 함께 원복.
- **S4**(로그인 실패 뒤 성공, 계정 탈취 의심): 시험 계정(`zz_` 접두)의 로그인 실패 5회 뒤 성공 → 계정 잠금 + 세션 전부 회수, 자동 원복 안 됨. 관리자가 포털에서 잠금을 푼 뒤 `confirm-recovery`로 사람 복구 확인.
- **S8 → S10**: 스캔(404) + 로그인 실패로 S8이 IP를 차단, 같은 IP에 경계 차단 신호가 더해지면 같은 티켓이 S10으로 승격해 경계·앱을 함께 차단. 원복은 경계 → 앱 순서로 확인. S8은 TTL 20초 뒤 자동 원복.
- **S12**(요청 폭주): 가벼운 요청 120건을 몰아 보내도 서비스가 멀쩡하면(헬스체크 3회 모두 기준 이내) 티켓도 차단도 만들지 않음 — "무해한 폭주는 차단 안 함" 설계를 실측으로 확인.
- 시험 중 발견: Graylog의 S8·S10 정의가 같은 트래픽에 동시에 발동해 `ip_block`이 중복 기록되는 경쟁 조건 1건 → 엔진 판단·조치 구간을 직렬화해 수정(상세: [docs/PROVENANCE.md](docs/PROVENANCE.md)).

나머지(Wazuh 파일 변조 복구 M6, N=5 반복 측정·원클릭 설치 M7)는 아직입니다. 단계별 계획은 [docs/PLAN.md](docs/PLAN.md), 구현할 동작의 기준은 [docs/BEHAVIOR-SPEC.md](docs/BEHAVIOR-SPEC.md)입니다.

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
.\scripts\test.ps1   # 린트 + 테스트
```

### 관제 스택(Graylog)과 S1 탐지

```powershell
python -m nobugs_tools.make_env                                         # .env 생성(무작위 비밀값, 콘솔 출력 없음)
docker compose -f infra/docker-compose.yml --env-file .env up -d        # Graylog+OpenSearch+MongoDB (웹 127.0.0.1:9100)
python -m nobugs_tools.graylog setup                                    # GELF 입력 + S1 탐지 정의 올리기(멱등)
$env:NB_GELF_ENABLED='true'; $env:NB_GELF_PORT='12301'                  # 포털 이벤트를 Graylog로 보내기
python -m nobugs_tools.attacks s1 --source 127.0.0.2 --user victim_a    # 공격 재현(루프백 전용)
python -m nobugs_tools.graylog events                                   # 발동한 이벤트 보기(최대 약 1분 뒤)
```

### 대응 엔진(S1)

```
python -m nobugs_tools.make_env                      # 엔진 키·포털 대응 키·경계 키가 .env에 덧붙음(기존 값은 유지)
python -m uvicorn nobugs_portal.control:control_factory --factory --port 5101 --app-dir src   # 포털 대응 API(별도 프로세스)
python -m uvicorn nobugs_boundary.app:boundary_factory --factory --port 5300 --app-dir src    # 경계 시뮬레이터(S10, 선택)
python -m nobugs_engine                              # 대응 엔진 http://127.0.0.1:5200 (티켓·알림 화면 포함)
python -m nobugs_tools.graylog setup --engine-url http://host.docker.internal:5200/webhook/graylog          # 모의 실행 모드
python -m nobugs_tools.graylog setup --engine-url http://host.docker.internal:5200/webhook/graylog --live   # 실제 조치 모드
```

엔진은 기본이 **모의 실행**입니다(`NB_ENGINE_DRY_RUN=false` 또는 알림 본문의 `dry_run:false`로만 실제 차단). 자동 원복 대기 시간은 `NB_ENGINE_RELEASE_TTL`(기본 90초).

### 프론트(React) 빌드·실행

```powershell
cd web; npm ci; npm run build          # 타입 검사 + 빌드 -> web/dist (포털이 / 로 서빙)
npm test                                # 단위 테스트(vitest)
npm run test:e2e                        # 실제 브라우저 E2E(Playwright, 임시 DB로 서버를 직접 띄움)
cd ..; $env:NB_DATABASE_URL='sqlite:///instance/portal.sqlite3'
.\.venv\Scripts\python.exe -m nobugs_portal.cli seed-demo                 # 시연 계정 3개(비밀번호는 한 번만 표시)
.\.venv\Scripts\python.exe -m uvicorn nobugs_portal.app:public_factory --factory --port 5100 --app-dir src
```

## 실행 (최종 목표)

`docker compose up -d` 와 설치 스크립트 한 번으로 전체가 뜨는 것이 최종 목표입니다(M7).

## 개발 방식

- 동작 명세와 테스트를 먼저 쓰고 구현합니다. 각 단계는 시연 가능한 결과로 끝납니다.
- AI 코딩 도구(Claude Code)를 보조로 사용합니다. 설계 결정과 검증은 본인이 합니다.
