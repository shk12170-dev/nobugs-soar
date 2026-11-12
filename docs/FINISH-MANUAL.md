# M7 마무리 매뉴얼 (남은 일 끝내기)

이 문서는 nobugs-soar의 마지막 단계(M7)에서 **남은 일을 혼자 순서대로 끝내기 위한 실습 안내서**입니다.
명령은 모두 Windows PowerShell 기준이고, 저장소 폴더(예: `C:\work\nobugs-soar`)에서 실행합니다.
실행 방법·새 케이스 구현 실습은 [MANUAL.md](MANUAL.md), 전체 구조는 [ARCHITECTURE.md](ARCHITECTURE.md)를 봅니다.

> 작성 기준: 2026-11-12, README·RETROSPECTIVE·PR #4 기준.
> 이 문서의 명령 중 **"예시"라고 표시한 이름(환경 변수·파일 이름)은 아직 저장소에 없는 제안**입니다.

---

## 0. 한눈에 보기 (체크리스트)

| 순서 | 할 일 | 필수? | 예상 시간 |
|---|---|---|---|
| 1 | `chore/m7-verification` 브랜치 커밋 → PR → 머지 | 필수 | 30분 |
| 2 | PR #4(Ubuntu 26.04 에이전트)로 S7 실제 시험 → PR 정리 | 필수 | 1시간 |
| 3 | 회고 "느낀 점" 직접 쓰기 | 필수 | 30분 |
| 4 | README "알려진 한계" 표 정리 | 필수 | 10분 |
| 5 | (선택) S7 N=5 재측정 | 선택 | 1시간 이상 |
| 6 | (선택) pfSense 차단 자동화 | 선택 | 하루 이상 |

순서가 중요합니다. **1번을 먼저 끝내야** 2번에서 브랜치가 꼬이지 않습니다.

---

## 1. `chore/m7-verification` 브랜치 커밋하고 머지하기

### 1-1. 용어 먼저

- **브랜치(branch)**: 원본(main)을 건드리지 않고 따로 작업하는 사본 줄기입니다.
- **커밋(commit)**: 지금까지 바꾼 내용을 "저장 지점" 하나로 묶는 것입니다.
- **푸시(push)**: 내 PC의 커밋을 GitHub에 올리는 것입니다.
- **PR(Pull Request)**: "이 브랜치를 main에 합쳐 주세요"라는 요청서입니다. CI(자동 테스트)가 여기서 돕니다.

### 1-2. 무엇이 바뀌었는지 확인

```powershell
git switch chore/m7-verification   # 이미 이 브랜치라면 생략
git status                         # 바뀐 파일 목록
git diff --stat                    # 파일별로 몇 줄 바뀌었는지
```

### 1-3. Ubuntu 26.04 변경은 따로 떼어 두기 (권장)

이 브랜치에는 "설치 시험 결과 문서 + 설치 스크립트 보완 + 에이전트 Ubuntu 26.04" 세 가지가 섞여 있습니다.
그런데 **26.04는 아직 S7까지 시험하지 않았습니다.** 시험 안 된 변경이 섞이면, 문제가 생겼을 때 어느 변경 탓인지 알기 어렵습니다.
그래서 26.04 변경은 PR #4에서 따로 다루는 것을 권장합니다.

```powershell
git diff infra/wazuh/agent          # 26.04 관련 변경이 이 폴더에 있는지 확인
git restore infra/wazuh/agent/Dockerfile   # 이 파일 변경만 되돌림(나머지 변경은 그대로)
```

> 주의: `git restore`는 그 파일의 **커밋 안 한 변경을 지웁니다.** 되돌리기 어려우니, 먼저 아래처럼 백업해 두세요.
> `Copy-Item infra/wazuh/agent/Dockerfile $HOME\Dockerfile.2604.bak`
>
> 만약 설치 스크립트 보완이 26.04에 꼭 필요해서 떼어낼 수 없다면, 떼지 말고 **2장의 S7 시험을 먼저 한 뒤** 커밋하세요.

### 1-4. 테스트 → 커밋 → 푸시

```powershell
.\scripts\test.ps1                 # 린트 + 테스트. 실패하면 커밋하지 말고 먼저 고칩니다.
git add -A
git status                         # .env 같은 비밀 파일이 목록에 없는지 꼭 확인!
git commit -m "chore(m7): 새 클론 setup.ps1 설치 시험 결과 반영, 설치 스크립트 보완"
git push -u origin chore/m7-verification
```

`.env`가 `git status`에 보이면 멈추고 `.gitignore`를 확인합니다. 비밀값은 절대 올리지 않습니다.

### 1-5. PR 만들고 머지

1. GitHub 저장소 화면 위쪽에 뜨는 **Compare & pull request** 버튼을 누릅니다.
2. 제목은 커밋 메시지와 같게, 본문에는 "무엇을 확인했는지(새 클론 setup.ps1 → S8 한 사이클)"를 짧게 적습니다.
3. 아래 **Checks**가 Python 3.12·3.14 둘 다 초록색이 될 때까지 기다립니다.
4. 초록색이면 **Squash and merge** → **Confirm**. 빨간색이면 눌러서 로그를 보고 고친 뒤 다시 push 합니다.
5. 머지 후 내 PC도 최신으로 맞춥니다.

```powershell
git switch main
git pull
```

---

## 2. PR #4: Ubuntu 26.04 에이전트로 S7 시험하기

PR #4는 Dependabot(의존성 자동 업데이트 봇)이 만든 것으로, `infra/wazuh/agent`의 기반 이미지를 `ubuntu:24.04` → `ubuntu:26.04`로 바꿉니다.
이미지 빌드는 됐지만 **"매니저와 연결 → FIM 감지 → S7 복구"까지 도는지는 아직 모릅니다.** 이걸 확인하는 게 목표입니다.

### 2-1. PR 브랜치 받기

1장 머지 뒤라면 PR #4가 main보다 뒤처져 있을 수 있습니다. PR #4 화면에 댓글로 `@dependabot rebase`를 남기면 봇이 최신 main 위로 다시 올려 줍니다(1~2분).

```powershell
git fetch origin
git switch -c test/ubuntu-2604 origin/dependabot/docker/infra/wazuh/agent/ubuntu-26.04
```

### 2-2. 에이전트 다시 빌드하고 띄우기

```powershell
docker compose -f infra/docker-compose.yml --env-file .env build --no-cache wazuh-agent
docker compose -f infra/docker-compose.yml --env-file .env up -d wazuh-manager wazuh-agent
```

`--no-cache`는 예전 24.04 조각을 재사용하지 않고 처음부터 다시 만들라는 뜻입니다.

### 2-3. 단계별 확인 (하나라도 실패하면 거기서 멈추고 기록)

| 단계 | 명령 | 통과 기준 |
|---|---|---|
| ① OS 확인 | `docker compose -f infra/docker-compose.yml --env-file .env exec wazuh-agent cat /etc/os-release` | `VERSION_ID="26.04"` |
| ② 에이전트 연결 | `docker compose -f infra/docker-compose.yml --env-file .env exec wazuh-manager /var/ossec/bin/agent_control -l` | 에이전트가 `Active` |
| ③ 기준본 저장 | `.\.venv\Scripts\python.exe -m nobugs_portal.cli seed-baseline` | 오류 없음 |
| ④ bridge 실행(새 터미널) | `.\.venv\Scripts\python.exe -m nobugs_tools.wazuh_bridge --alerts-log infra/wazuh/logs/alerts/alerts.json --agent-prefix /nobugs/web-root` | 대기 상태로 떠 있음 |
| ⑤ 변조 공격 | `.\.venv\Scripts\python.exe -m nobugs_tools.attacks s7 --file-key index.html` | 공격 완료 메시지 |
| ⑥ 결과 | 제어판 http://127.0.0.1:5102 또는 엔진 http://127.0.0.1:5200 | 새 S7 티켓이 `restored`, 파일이 기준본으로 돌아옴 |

포털·대응 API·엔진은 미리 각자 터미널에서 `python -m nobugs_tools.run portal` 등으로 띄워 둡니다(README "처음부터 한 번에" 참고).

②에서 Active가 안 되면 에이전트 로그를 봅니다.

```powershell
docker compose -f infra/docker-compose.yml --env-file .env logs --tail 100 wazuh-agent
```

흔한 원인: 26.04에서 Wazuh `.deb` 설치에 필요한 패키지가 빠졌거나 이름이 바뀜, 매니저와 에이전트 버전 불일치.

### 2-4. 결과에 따라 PR 정리

- **전부 통과** → 결과를 PR #4 댓글로 남기고(날짜, 단계 ①~⑥ 통과, 티켓 번호) 머지합니다.
  README·MEASUREMENTS에 "에이전트 Ubuntu 26.04에서 S7 확인(날짜)" 한 줄을 추가하는 커밋을 별도로 올립니다.
- **실패** → 실패 단계와 로그 요약을 댓글로 남기고 PR을 **Close** 합니다. 24.04를 유지합니다.
  Dependabot이 같은 PR을 또 만들지 않게 하려면 `.github/dependabot.yml`의 docker 항목에 아래를 추가합니다.

```yaml
    ignore:
      - dependency-name: "ubuntu"
        versions: ["26.04"]
```

- 1-3에서 26.04 변경을 떼어 두었다면, 백업 파일(`Dockerfile.2604.bak`)은 PR #4와 내용이 같은지만 보고 지워도 됩니다.

시험이 끝나면 정리합니다.

```powershell
git switch main
git branch -D test/ubuntu-2604     # 로컬 시험 브랜치 삭제(원격 PR에는 영향 없음)
```

---

## 3. 회고 "느낀 점" 쓰기

[RETROSPECTIVE.md](RETROSPECTIVE.md)의 맨 아래 "(본인 작성)" 칸입니다. 이 칸은 면접에서 가장 많이 질문받는 부분이라 **본인 말로** 쓰는 게 좋습니다.
아래 질문에 한두 문장씩 답하면 그대로 초안이 됩니다.

1. 팀에서 4명·PC 4대로 하던 것을 혼자·PC 1대로 다시 만들면서 **가장 크게 달라진 점**은?
2. 위 "겪은 문제" 표 중 **가장 오래 막혔던 것** 하나와, 그때 어떻게 원인을 좁혀 갔는지?
3. "에러 없음 ≠ 동작함"을 실제로 겪은 순간(S7 이벤트가 조용히 안 만들어진 일 등)에 무엇을 느꼈는지?
4. AI 코딩 도구를 쓰면서 **내가 직접 판단해야 했던 것**은 무엇이었는지?
5. 다시 한다면 처음부터 다르게 할 것 한 가지는?

팁: "~를 배웠다"보다 "~해서 ~했고, 다음엔 ~하겠다"처럼 구체적인 행동으로 끝내면 읽는 사람이 이해하기 쉽습니다.

---

## 4. README "알려진 한계" 표 정리

1~2장을 마치면 README의 아래 줄을 실제 결과에 맞게 고칩니다.

| 줄 | 고칠 내용 |
|---|---|
| 새 클론 전체 설치 | "새 클론에서 setup.ps1로 docker 스택까지 설치 → S8 한 사이클 확인(날짜)"로 바꾸거나, 남은 범위(예: -WithWazuh)만 남김 |
| S7 N=5 측정 4/5 | 5장 재측정을 했다면 결과로 교체 |
| 상단 "상태" 문단 | M7 완료 여부 반영 |

검증 표는 **실제로 확인한 것만** "확인"으로 바꾸는 기존 원칙을 지킵니다.

---

## 5. (선택) S7 N=5 재측정

4/5였던 이유는 기준본 파일 4개를 돌려 쓰다 5회차가 재알림 묵음 기간(10분)에 걸렸기 때문입니다. 측정 도구는 이미 보완돼 있습니다.

```powershell
.\.venv\Scripts\python.exe -m nobugs_tools.measure --case S7 --rounds 5 --s7-wait-grace --out docs/MEASUREMENTS.md
```

- `--s7-wait-grace`는 묵음 10분을 기다리므로 **5회차 앞에서 10분 넘게 멈춘 것처럼 보이는 게 정상**입니다.
- 측정 중에는 Graylog·엔진·Wazuh를 재시작하지 않습니다.
- 5/5가 나오면 README 검증 표와 "알려진 한계"의 S7 줄을 고칩니다.

---

## 6. (선택) pfSense 차단 자동화 설계 안내

지금은 pfSense 로그 **수집**만 되고, 엔진이 pfSense에서 IP를 **막는** 것은 범위 밖입니다(S10의 경계 차단은 시뮬레이터 `nobugs_boundary`).
아래는 시뮬레이터 자리에 실제 pfSense를 끼우는 방법입니다. 하루 이상 걸리니 발표·제출 뒤에 하는 것을 권장합니다.

### 6-1. 원리 (쉽게)

pfSense 안에는 **"차단 명단(테이블)"**을 만들 수 있습니다. "이 명단에 있는 IP는 막는다"는 규칙을 하나 걸어 두고,
엔진은 명단에 IP를 **넣고(차단) 빼기(원복)**만 합니다. 규칙 자체는 건드리지 않으니 안전하고, 되돌리기도 쉽습니다.

| 하는 일 | pfSense 셸 명령 |
|---|---|
| 차단 | `pfctl -t NOBUGS_BLOCK -T add 1.2.3.4` |
| 기존 연결 끊기 | `pfctl -k 1.2.3.4` |
| 효과 확인 | `pfctl -t NOBUGS_BLOCK -T show` (명단에 있는지) |
| 원복 | `pfctl -t NOBUGS_BLOCK -T delete 1.2.3.4` |

### 6-2. pfSense 쪽 준비 (웹 화면에서)

1. **Firewall → Aliases → Add**: 이름 `NOBUGS_BLOCK`, 종류 Host(s), 내용은 비워 둠.
2. **Firewall → Rules → (S10 대상 인터페이스)**: 맨 위에 Block 규칙 추가, Source = `NOBUGS_BLOCK`, 로그 켜기.
3. **System → Advanced → Admin Access → Secure Shell** 켜기. 비밀번호 대신 **SSH 키** 로그인을 쓰고, 개인 키 경로는 `.env`에만 둡니다.

알아 둘 한계: pfSense에서 필터를 다시 불러오면(설정 저장 등) 명령으로 넣은 명단이 비워질 수 있습니다. 그래서 효과 확인 단계에서 매번 `-T show`로 실제로 들어 있는지 봐야 합니다.

### 6-3. 저장소 쪽 구현 순서

1. 엔진이 경계 시뮬레이터를 부르는 곳을 찾습니다.
   `git grep -n -i boundary src`
2. 같은 모양(차단·확인·원복)의 **pfSense 어댑터**를 새 파일로 만듭니다. SSH 실행 부분은 함수 하나로 분리해,
   테스트에서는 가짜 함수로 바꿔 끼울 수 있게 합니다.
3. 환경 변수로 고릅니다. 예시: `NB_BOUNDARY_MODE=simulator`(기본) / `pfsense`.
4. **테스트를 먼저** 씁니다(기존 개발 방식): 차단 명령 문자열, 확인 실패 시 None 반환, 원복 순서(경계 → 앱) 유지.
5. 엔진 기본값은 계속 **모의 실행(dry_run)**으로 둡니다.
6. 실제 시험: S10 공격 → pfSense `-T show`에 IP 있음 → 그 IP로 새 연결 timeout → 다른 IP 정상 → TTL 뒤 명단에서 빠짐 → README 검증 표의 pfSense 줄 갱신.

안전 수칙: 랩 망(172.16.50.0/24) 안에서만, 시험 IP만 넣습니다. 관리 PC의 IP가 명단에 들어가면 pfSense 웹 화면에 못 들어갈 수 있으니, 어댑터에서 **관리 IP는 차단 거부**하도록 막아 둡니다.

---

## 7. 막혔을 때

| 증상 | 먼저 볼 것 |
|---|---|
| 엔진이 Graylog 알림을 401로 거부 | uvicorn을 직접 띄웠는지 → `python -m nobugs_tools.run ...`로 띄우기(.env를 읽음) |
| 측정이 timeout | Graylog 평가 주기(60초)보다 기다리는 시간이 짧은지 |
| 로그인 시도가 429 | 같은 IP 재사용 → `--salt`가 바뀌었는지 |
| n8n이 죽음 | 메모리 1536m 설정 유지 여부 |
| pfSense 로그가 안 들어옴 | `syslog_relay`가 떠 있는지, Windows 방화벽 UDP 1514 규칙 |

자세한 원인과 수정 이력은 [PROVENANCE.md](PROVENANCE.md)에 있습니다.
