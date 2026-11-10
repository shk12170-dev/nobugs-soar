# nobugs-soar

공공기관 민원 포털을 공격 → **탐지(Graylog·Wazuh)** → **자동 대응(Python 대응 엔진)** → **차단·잠금·복구** → **티켓·효과 확인·자동 원복**까지 한 흐름으로 보여 주는 보안 관제·자동 대응(SOAR) 프로젝트입니다.

팀 캡스톤(NoBugs 1조, 2026.10~11)에서 다뤘던 문제를 **혼자, 처음부터 새로 설계·구현**하는 저장소입니다. 이전에 만든 재현판(`haedam-soar`, 비공개)과 달리 포털·대응 로직·탐지 규칙을 본인 코드로 새로 작성합니다. 출처·작성 규칙은 [docs/CLEANROOM.md](docs/CLEANROOM.md)에 있습니다.

## 상태

**M6 완료, M7(측정·배포·문서) 진행 중 — S1·S4·S7·S8·S10·S12 여섯 케이스가 탐지부터 자동(또는 사람) 원복까지 자동으로 돕니다.** 파이썬 테스트 306건, 프론트 단위 23건, 브라우저 E2E 7건이 통과합니다.

실제 시험(2026-11-10, Graylog·포털·대응 엔진·경계 시뮬레이터를 실제로 띄워 확인):
- **S1**: 공격 후 10초 만에 차단·효과 확인, TTL 30초 뒤 자동 원복, 같은 IP의 티켓 2개도 교착 없이 함께 원복.
- **S4**(로그인 실패 뒤 성공, 계정 탈취 의심): 시험 계정(`zz_` 접두)의 로그인 실패 5회 뒤 성공 → 계정 잠금 + 세션 전부 회수, 자동 원복 안 됨. 관리자가 포털에서 잠금을 푼 뒤 `confirm-recovery`로 사람 복구 확인.
- **S8 → S10**: 스캔(404) + 로그인 실패로 S8이 IP를 차단, 같은 IP에 경계 차단 신호가 더해지면 같은 티켓이 S10으로 승격해 경계·앱을 함께 차단. 원복은 경계 → 앱 순서로 확인. S8은 TTL 20초 뒤 자동 원복.
- **S12**(요청 폭주): 가벼운 요청 120건을 몰아 보내도 서비스가 멀쩡하면(헬스체크 3회 모두 기준 이내) 티켓도 차단도 만들지 않음 — "무해한 폭주는 차단 안 함" 설계를 실측으로 확인.
- 시험 중 발견: Graylog의 S8·S10 정의가 같은 트래픽에 동시에 발동해 `ip_block`이 중복 기록되는 경쟁 조건 1건 → 엔진 판단·조치 구간을 직렬화해 수정(상세: [docs/PROVENANCE.md](docs/PROVENANCE.md)).

실제 시험(2026-11-10, 실제 Wazuh 매니저+에이전트를 띄워 확인 — **S7은 Active Response를 쓰지 않고 이 저장소의 설계(Wazuh FIM → `nobugs_tools.wazuh_bridge` → Graylog 집계 → 대응 엔진 웹훅)로 복구함**):
- **S7**(홈페이지 변조): 공격 스크립트로 포털이 실제로 서빙하는 파일(`web/dist`)을 직접 바꿔치고 방문자 접근을 재현 → 실제 Wazuh 에이전트가 실시간 FIM으로 변조를 감지 → bridge가 기준본과 다를 때만 `tamper-signal`을 Graylog로 전달 → 변조 신호 + 방문자 접근(2xx)이 같은 자산·파일에서 10분 안에 모이면 Graylog가 엔진 웹훅을 호출 → 엔진이 포털 대응 API로 파일을 기준본으로 복구하고 티켓이 `restored`로 바로 넘어감(복구 자체가 원복이라 자동 원복은 없음) → 사람이 `close`로 마무리. 기준본에 없는 새 파일이면 격리(`quarantine`)로 분기.
- 시험 중 발견·수정한 버그 2건(상세: [docs/PROVENANCE.md](docs/PROVENANCE.md)): ① Graylog 필드 값 계산이 `src_ip`를 필수로 요구해 `tamper-signal`(src_ip 없음) 쪽에서 이벤트 생성 자체가 조용히 실패 → S7만 `require_values=false`로 완화. ② 엔진 웹훅 알림 본문에 `asset_id`/`file_key`가 전혀 담겨 있지 않아 엔진이 매번 "보호 대상 아님"으로 조용히 무시(Graylog는 2xx로 보고 성공 처리) → 본문에 두 필드 추가.

M7 반복 측정 자동화(`python -m nobugs_tools.measure`)는 실제 서버로 S1·S4·S8·S10·S12를 각 2회씩 완주 확인했습니다(결과·시험 중 발견한 측정 도구 자체의 결함 3건은 [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md)). 원클릭 설치(`scripts\setup.ps1`)도 실제로 두 번 돌려 확인했습니다 — .env 생성, docker compose up, Graylog 준비 대기, S7 기준본 저장, Graylog 정의 설정, 상태 대조까지 한 번에 하고 끝에 포털·엔진을 띄우는 다음 명령을 안내합니다(발견·수정한 결함은 [docs/PROVENANCE.md](docs/PROVENANCE.md)). S7을 포함한 전체 케이스 N=5 측정, README 검증 표·아키텍처 그림·스크린샷·회고는 아직입니다. 단계별 계획은 [docs/PLAN.md](docs/PLAN.md), 구현할 동작의 기준은 [docs/BEHAVIOR-SPEC.md](docs/BEHAVIOR-SPEC.md)입니다.

## 구성 (목표)

```
공격 스크립트 ─▶ 포털(FastAPI + React) ──GELF──▶ Graylog ──탐지 이벤트──▶ 대응 엔진(Python)
                     ▲                                  ▲                          │ 차단·잠금·복구
                     │                                  └── Wazuh(FIM) 경보 ───────┤
                     └──────── 차단 목록·세션 회수 ◀───────────────────────────────┤
                                                                   티켓 저장소·대시보드·알림 ◀┘
```

## 처음부터 한 번에(원클릭 설치)

```powershell
.\scripts\setup.ps1              # venv·deps·프론트 빌드·.env·docker compose up·Graylog 설정·상태 대조까지 전부
.\scripts\setup.ps1 -WithWazuh   # S7용 wazuh-manager+agent도 같이(무거움, 측정일에만)
.\scripts\setup.ps1 -Live        # Graylog 알림을 실제 조치 모드로(기본은 모의 실행)
```

끝나면 상태 대조 결과와 함께 포털·대응 API·엔진을 띄우는 명령을 안내합니다. 세 프로세스는 각자 터미널에서
보며 시연해야 해서 이 스크립트가 직접 띄우지는 않습니다. 이미 떠 있는 스택에 설정만 다시 올리려면
`-SkipDocker`, 프론트를 다시 빌드하지 않으려면 `-SkipFrontend`를 붙입니다.

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

### Wazuh FIM과 S7(홈페이지 변조)

공식 `wazuh/wazuh-agent` 이미지는 없어 매니저와 같은 버전의 `.deb`로 직접 빌드한다(인덱서·대시보드는 쓰지 않음 — 매니저가 로컬에 쓰는 `alerts.json`을 bridge가 직접 읽는다). Active Response는 쓰지 않고 탐지만 매니저로 보낸 뒤 Graylog 집계·엔진 웹훅으로 복구한다.

```powershell
docker compose -f infra/docker-compose.yml --env-file .env up -d wazuh-manager wazuh-agent   # 매니저+에이전트(web/dist를 FIM으로 감시)
.\.venv\Scripts\python.exe -m nobugs_portal.cli seed-baseline                                 # 지금 web/dist를 기준본으로 저장
python -m nobugs_tools.wazuh_bridge --alerts-log infra/wazuh/logs/alerts/alerts.json --agent-prefix /nobugs/web-root   # 변조 신호를 Graylog로 중계
python -m nobugs_tools.attacks s7 --file-key index.html                                       # 변조 재현(파일을 직접 바꾼 뒤 방문자 접근까지)
```

Git Bash에서 `--agent-prefix`처럼 `/`로 시작하는 인자는 Windows 경로로 자동 변환되니 `MSYS_NO_PATHCONV=1`을 붙인다.

### 반복 측정(M7)

포털·대응 API·엔진·Graylog가 뜬 상태에서(S7도 재려면 Wazuh까지) 케이스별 N회를 공격부터 효과 확인까지 재고
표로 남긴다. 결과는 [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md)에 기록한다.

```powershell
python -m nobugs_tools.measure --case S1,S4,S8,S10,S12 --rounds 5 --out docs/MEASUREMENTS.md
python -m nobugs_tools.measure --all --rounds 5   # S7까지 포함(Wazuh 필요)
```

도구를 다시 돌릴 때는 `--salt`(기본은 실행 시각 기준)가 바뀌어 출발지 IP가 겹치지 않는다 — 같은 IP를 또 쓰면
포털의 로그인 횟수 제한(출발지당 5분에 20회)에 걸려 실제로는 통과할 시도도 막힌다.

### 프론트(React) 빌드·실행

```powershell
cd web; npm ci; npm run build          # 타입 검사 + 빌드 -> web/dist (포털이 / 로 서빙)
npm test                                # 단위 테스트(vitest)
npm run test:e2e                        # 실제 브라우저 E2E(Playwright, 임시 DB로 서버를 직접 띄움)
cd ..; $env:NB_DATABASE_URL='sqlite:///instance/portal.sqlite3'
.\.venv\Scripts\python.exe -m nobugs_portal.cli seed-demo                 # 시연 계정 3개(비밀번호는 한 번만 표시)
.\.venv\Scripts\python.exe -m uvicorn nobugs_portal.app:public_factory --factory --port 5100 --app-dir src
```

## 개발 방식

- 동작 명세와 테스트를 먼저 쓰고 구현합니다. 각 단계는 시연 가능한 결과로 끝납니다.
- AI 코딩 도구(Claude Code)를 보조로 사용합니다. 설계 결정과 검증은 본인이 합니다.
