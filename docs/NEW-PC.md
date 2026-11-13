# 다른 PC에서 이어서 작업하기

새 PC(Windows 10/11)에서 이 프로젝트를 처음부터 받아 실행하고, 하던 작업을 이어 가는 안내서다. 위에서부터
순서대로 하면 된다.

> 2~6절(받기 → 설치 → 서버 → 확인)은 2026-11-12에 GitHub에서 새로 받은 폴더로 그대로 해 보고 확인한 경로다
> (새 docker 볼륨에서 설치 끝까지, S8 한 사이클 21초 — [PROVENANCE.md](PROVENANCE.md)). 1절 프로그램 설치는 PC마다
> 달라서 직접 확인하지 못했다.

목차

0. [무엇이 옮겨지고 무엇을 새로 만드나](#0-무엇이-옮겨지고-무엇을-새로-만드나)
1. [프로그램 설치(처음 한 번)](#1-프로그램-설치처음-한-번)
2. [저장소 받기](#2-저장소-받기)
3. [한 번에 설치하기](#3-한-번에-설치하기)
4. [(선택) n8n 경유 S1 연결](#4-선택-n8n-경유-s1-연결)
5. [서버 띄우기](#5-서버-띄우기)
6. [잘 되는지 확인](#6-잘-되는지-확인)
7. [하던 작업 이어 가기](#7-하던-작업-이어-가기)
8. [두 PC를 오가며 작업할 때 규칙](#8-두-pc를-오가며-작업할-때-규칙)
9. [(선택) pfSense 로그 수집](#9-선택-pfsense-로그-수집)
10. [Claude Code로 이어서 할 때](#10-claude-code로-이어서-할-때)
11. [막혔을 때](#11-막혔을-때)

---

## 0. 무엇이 옮겨지고 무엇을 새로 만드나

**코드·문서·작업 브랜치는 전부 GitHub에 있다.** 새 PC에서는 받기만 하면 된다.

| 옮겨지는 것(GitHub) | 새 PC에서 새로 만들어지는 것(옮기지 않음) |
| --- | --- |
| `main`의 모든 코드·문서·시험 | `.env` 비밀값: 설치 때 무작위로 새로 만든다. 이전 PC 것을 복사하지 않는다 |
| S6 실습 브랜치 `feat/s6-admin-auth-fail`(6-1까지) | 포털 DB·엔진 티켓 기록(`instance/`): 빈 상태로 시작 |
| | Graylog·n8n·Wazuh 데이터(docker 볼륨): 새로 시작 |
| | 시연 계정 비밀번호: 설치 때 새로 만들어 **한 번만** 보여 준다 |
| | pfSense VM: 이전 PC의 VMware 안에 있다(9절) |

> 이전 PC의 티켓 기록·Graylog 검색 기록은 새 PC로 오지 않는다. 문서에 남긴 측정 결과·스크린샷은 저장소에 있으니
> 걱정하지 않아도 된다.

---

## 1. 프로그램 설치(처음 한 번)

> **Windows만 설치된 빈 PC라면** 이 절 대신 [WINDOWS-SETUP.md](WINDOWS-SETUP.md)를 먼저 끝까지 한다(가상화·WSL2·
> Docker·Git·Python·Node·Claude까지 개발 PC와 같은 버전 표 포함). 끝나면 2절로 온다.

필요한 것: **RAM 16GB 이상**(Graylog·OpenSearch·Wazuh가 무겁다), 디스크 여유 20GB 이상.

PowerShell을 열고 아래를 하나씩 실행한다. 이미 설치된 것은 건너뛴다.

```powershell
winget install --id Git.Git -e
```

```powershell
winget install --id Python.Python.3.14 -e
```

```powershell
winget install --id OpenJS.NodeJS.LTS -e
```

```powershell
winget install --id Docker.DockerDesktop -e
```

```powershell
winget install --id GitHub.cli -e
```

- `winget`에서 버전을 못 찾으면 공식 사이트에서 받아도 된다. 필요한 버전은 Python **3.12 이상**(개발 PC는 3.14), Node.js **22 이상**이다.
- Python 설치 화면이 나오면 **"Add python.exe to PATH"를 체크**한다.
- **설치가 끝나면 PowerShell 창을 닫고 새로 연다.** 새 창이어야 방금 설치한 명령을 찾는다.
- Docker Desktop은 처음 한 번 직접 실행해서, WSL2 설치 안내가 나오면 따르고(재부팅이 필요할 수 있다) 로그인은 건너뛰어도 된다.
  왼쪽 아래가 **"Engine running"**이 될 때까지 기다린다.

설치 확인(버전이 나오면 OK):

```powershell
git --version; python --version; node --version; docker --version; gh --version
```

GitHub CLI 로그인(PR을 만들고 머지할 때 쓴다):

```powershell
gh auth login
```

질문이 나오면 GitHub.com → HTTPS → 브라우저로 로그인을 고른다.

---

## 2. 저장소 받기

폴더 위치는 자유지만, 이 문서는 이전 PC와 같은 `C:\shk\nobugs-soar`를 기준으로 쓴다.

```powershell
mkdir C:\shk -Force; cd C:\shk
```

```powershell
git clone https://github.com/shk12170-dev/nobugs-soar.git
```

```powershell
cd C:\shk\nobugs-soar
```

커밋에 남을 이름·이메일을 이 PC에 한 번 정한다(GitHub 계정과 같게):

```powershell
git config --global user.name "shk12170-dev"
```

```powershell
git config --global user.email "<GitHub에 쓰는 이메일>"
```

---

## 3. 한 번에 설치하기

**Docker Desktop이 켜져 있어야 한다.** 그다음 저장소 폴더에서:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Live
```

- `-ExecutionPolicy Bypass`는 **이번 실행에만** 스크립트 실행을 허용한다. 새 PC는 기본 설정 때문에 `.ps1`이 막혀
  있는 경우가 많다. PC 보안 설정 자체는 바꾸지 않는다.
- `-Live`는 탐지가 오면 **실제로 차단**하게 한다. 빼면 모의 실행만 한다.
- S7(홈페이지 변조)까지 하려면 `-WithWazuh`를 더 붙인다. 무거우니 S7을 할 때만 붙인다.

이 한 줄이 하는 일: 가상환경(`.venv`)·파이썬 패키지 → 프론트 빌드 → `.env`(무작위 비밀값) → docker(Graylog 등)
→ Graylog 준비 대기 → S7 기준본 → 시연 계정 → Graylog 탐지 정의 6개 → 상태 표. **처음에는 10~20분** 걸린다.

**꼭 할 일 — 시연 계정 비밀번호 적어 두기.** 중간에 아래처럼 나온다.

```
citizen_demo  ••••••••
staff_demo    ••••••••
admin_demo    ••••••••
위 비밀번호는 지금만 표시됩니다.
```

이 비밀번호는 **다시 볼 수 없다.** 비밀번호 관리 프로그램이나 개인 메모에 적어 둔다. 저장소 파일·채팅에는 붙여
넣지 않는다.

끝나면 나오는 `=== 설치 상태 ===` 표가 전부 `확인`·`running`이면 성공이다.

> Graylog 웹(`http://127.0.0.1:9100`) 로그인: 아이디 `admin`, 비밀번호는 `.env` 파일의
> `NB_GRAYLOG_ADMIN_PASSWORD` 값이다(메모장으로 `.env`를 열어 직접 본다).

---

## 4. (선택) n8n 경유 S1 연결

`setup.ps1`은 n8n을 올리지 않는다. 시연에서 "S1이 n8n을 거쳐 엔진으로 간다"를 보여 줄 때만 한다.

```powershell
docker compose -f infra/docker-compose.yml --env-file .env up -d n8n
```

```powershell
.\.venv\Scripts\python.exe -m nobugs_tools.n8n_setup
```

```powershell
.\.venv\Scripts\python.exe -m nobugs_tools.graylog setup --engine-url http://host.docker.internal:5200/webhook/graylog --n8n-url http://n8n:5678/webhook/s1 --live
```

n8n 관리 화면: `http://127.0.0.1:5678` (로그인 값은 `.env`의 `NB_N8N_USER`·`NB_N8N_PASSWORD`).

---

## 5. 서버 띄우기

PowerShell 창을 4개 열고, 각 창에서 `cd C:\shk\nobugs-soar` 한 뒤 하나씩 실행한다. 창은 켜 둔다(닫으면 서버가 꺼진다).

```powershell
.\.venv\Scripts\python.exe -m nobugs_tools.run portal
```

```powershell
.\.venv\Scripts\python.exe -m nobugs_tools.run control
```

```powershell
.\.venv\Scripts\python.exe -m nobugs_tools.run engine
```

```powershell
.\.venv\Scripts\python.exe -m nobugs_tools.run panel
```

필요할 때만 더 띄운다:

| 무엇 | 언제 | 명령 |
| --- | --- | --- |
| 경계 시뮬레이터(5300) | S10을 할 때 | `.\.venv\Scripts\python.exe -m nobugs_tools.run boundary` |
| Wazuh 브리지 | S7을 할 때(`-WithWazuh`로 설치했을 때) | 아래 |

```powershell
.\.venv\Scripts\python.exe -m nobugs_tools.wazuh_bridge --alerts-log infra/wazuh/logs/alerts/alerts.json --agent-prefix /nobugs/web-root
```

다음 날 다시 켤 때는 **Docker Desktop 실행 → (스택이 꺼져 있으면) 아래 명령 → 5절 서버 4개**만 하면 된다. 3절 설치는
다시 하지 않는다.

```powershell
docker compose -f infra/docker-compose.yml --env-file .env up -d
```

---

## 6. 잘 되는지 확인

1. 브라우저로 제어판 `http://127.0.0.1:5102`를 연다.
2. **「S8 웹 스캔→로그인」** 버튼을 누른다.
3. 보통 **1분 안에** 맨 위에 새 S8 티켓이 생기고 ①~⑤가 초록으로 찬다(Graylog가 1분마다 평가한다).
4. 90초쯤 뒤 ⑥ 원복이 켜지고 `restored`가 되면 전체 흐름이 정상이다.

시험·린트도 한 번 돌려 둔다(전부 통과해야 한다):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test.ps1
```

---

## 7. 하던 작업 이어 가기

| 작업 | 어디까지 했나 | 이어 가는 법 |
| --- | --- | --- |
| S6 실습(선택, 학습용) | 6-1 완료·푸시 | `git switch feat/s6-admin-auth-fail` 후 [MANUAL.md](MANUAL.md) **6-2**부터 |
| 내레이션 시연 영상(선택) | 대본·자막 GIF 있음 | [DEMO-SCRIPT.md](DEMO-SCRIPT.md) 트랙 A. 녹화는 Win+Alt+R(Xbox Game Bar) |
| 이력서 | 문안 완성 | [RESUME-PROJECT.md](RESUME-PROJECT.md)를 이력서에 옮겨 쓰기 |

S6 브랜치로 바꾼 뒤에는 **포털·엔진 창을 Ctrl+C로 껐다 다시 띄운다.** 서버는 켤 때의 코드로 돈다.

```powershell
git switch feat/s6-admin-auth-fail
```

---

## 8. 두 PC를 오가며 작업할 때 규칙

이것만 지키면 두 PC의 코드가 꼬이지 않는다.

1. **작업 시작 전**: 최신 내용을 받는다.

   ```powershell
   git pull
   ```

2. **작업 끝나면**: 커밋하고 올린다. 다른 PC에서 받을 수 있는 건 GitHub에 올린 것뿐이다.

   ```powershell
   git add -A
   ```

   ```powershell
   git commit -m "무엇을 했는지 한 줄"
   ```

   ```powershell
   git push
   ```

3. **같은 브랜치를 두 PC에서 동시에 고치지 않는다.** 한쪽에서 push한 뒤 다른 쪽에서 pull하고 이어 간다.
4. **`.env`는 PC마다 따로 둔다.** 복사하거나 커밋하지 않는다(`.gitignore`가 막고 있다). 각 PC의 Graylog·n8n은 그
   PC의 `.env`로 만들어졌다.
5. `git status`가 깨끗하지 않은데 PC를 옮겨야 하면, 끝나지 않은 작업이라도 브랜치에 커밋·push한다
   (예: `wip: 6-2 진행 중`). main에 바로 올리지 않는다.

---

## 9. (선택) pfSense 로그 수집

pfSense 방화벽 VM은 **이전 PC의 VMware 안**에 있다. 새 PC에서 방화벽 로그 수집까지 보여 주려면 VMware와 pfSense VM을
새 PC로 옮기거나 새로 설치해야 한다. 시연 트랙 A·B와 S1~S12에는 필요 없다.

한다면:
1. VMware에서 pfSense VM을 켜고, 새 PC의 VMnet 어댑터 IPv4 주소를 확인한다(`ipconfig`의 "VMware Network Adapter VMnetX").
2. `.env`의 `NB_SYSLOG_BIND`를 그 주소로 바꾼다. 이후 `setup.ps1`이 중계기를 자동으로 띄운다.
3. Windows 방화벽의 인바운드 UDP 1514 허용(랩 대역만)은 **직접** 설정한다.
4. 자세한 이유와 확인 방법은 README "pfSense 방화벽 로그 수집"을 본다.

---

## 10. Claude Code로 이어서 할 때

- Claude Code(데스크톱 앱 또는 터미널)에서 **`C:\shk\nobugs-soar` 폴더를 연다**(팀 저장소 폴더가 아니라).
- 이전 PC의 대화 기록·메모리는 새 PC로 오지 않는다. 대신 이렇게 시작하면 된다:
  "docs/NEW-PC.md와 docs/MANUAL.md를 읽고, S6 실습 6-2부터 단계별로 알려줘. 나는 초보라 직접 해 볼게."
- 비밀값(`.env`, 시연 계정 비밀번호, Graylog 관리자 비밀번호)은 채팅에 붙여 넣지 않는다.

---

## 11. 막혔을 때

| 증상 | 해결 |
| --- | --- |
| `.ps1 파일을 로드할 수 없습니다... 실행 정책` | 3절처럼 `powershell -ExecutionPolicy Bypass -File ...`로 실행 |
| `python`을 찾을 수 없음, 또는 Microsoft Store가 열림 | Python을 PATH 체크하고 다시 설치 → **새 PowerShell 창**. 그래도 Store가 열리면 Windows 설정 → 앱 → 고급 앱 설정 → 앱 실행 별칭에서 python 두 개를 끈다 |
| `npm`·`node`를 찾을 수 없음 | Node.js 설치 뒤 새 창. `node --version`이 22 이상인지 확인 |
| `failed to connect to the docker API` | Docker Desktop을 실행하고 "Engine running"까지 기다린다 |
| `Graylog 준비를 기다립니다...`에서 오래 멈춤 | 첫 실행은 몇 분 걸린다. 계속 안 되면 Docker Desktop → Settings → Resources에서 메모리를 늘리고, 다른 프로그램을 끈다 |
| 포트가 이미 사용 중(5100·9100 등) | 같은 서버가 이미 떠 있다. 해당 창을 찾아 Ctrl+C, 또는 PC를 다시 시작 |
| 설치 상태 표에서 `컨테이너 ...: 없음` | `docker compose -f infra/docker-compose.yml --env-file .env up -d` 후 다시 확인 |
| 공격 후 티켓이 안 생김 | 서버를 `nobugs_tools.run`으로 띄웠는지(5절), `setup.ps1`에 `-Live`를 줬는지, 1분 기다렸는지 확인. [MANUAL.md](MANUAL.md) 9절도 본다 |
| `git push`가 거절됨(rejected) | 다른 PC에서 먼저 올린 것이 있다. `git pull` 후 다시 `git push` |
