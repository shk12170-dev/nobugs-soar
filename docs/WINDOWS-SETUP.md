# 빈 Windows에서 작업 환경 똑같이 만들기

**Windows만 설치된 PC**를 이 프로젝트를 개발한 PC와 같은 작업 환경으로 만드는 안내서다. 이 문서를 끝내면
[NEW-PC.md](NEW-PC.md) 2절(저장소 받기)부터 이어 가면 된다.

> 아래 버전 표는 개발 PC에서 2026-11-13에 직접 확인한 값이다. 이 문서의 설치 절차 자체는 빈 PC에서 아직 돌려 보지
> 못했다. 막히는 곳이 있으면 11절을 먼저 보고, 실제로 겪은 내용을 이 문서에 보태 둔다.

목차

0. [목표 환경(개발 PC와 같은 구성)](#0-목표-환경개발-pc와-같은-구성)
1. [시작 전 확인: 사양·가상화·관리자 권한](#1-시작-전-확인-사양가상화관리자-권한)
2. [Windows 업데이트와 winget](#2-windows-업데이트와-winget)
3. [WSL2 켜기(Docker에 필요)](#3-wsl2-켜기docker에-필요)
4. [개발 도구 설치](#4-개발-도구-설치)
5. [Docker Desktop 처음 설정](#5-docker-desktop-처음-설정)
6. [Git·GitHub 설정](#6-gitgithub-설정)
7. [편집기·브라우저·Claude(작업 도구)](#7-편집기브라우저claude작업-도구)
8. [최종 점검](#8-최종-점검)
9. [(선택) VMware와 pfSense VM](#9-선택-vmware와-pfsense-vm)
10. [다음 단계](#10-다음-단계)
11. [막혔을 때](#11-막혔을-때)

---

## 0. 목표 환경(개발 PC와 같은 구성)

| 구분 | 도구 | 개발 PC 버전 | 꼭 필요한가 | 최소 요구 |
| --- | --- | --- | --- | --- |
| 운영체제 | Windows 11 Pro | 10.0.26100 | 필수 | Windows 10 22H2 / 11 (Home도 가능) |
| 하드웨어 | RAM | 16GB | 필수 | 16GB(Graylog·OpenSearch·Wazuh가 무겁다) |
| 리눅스 계층 | WSL | 2.7.12 | 필수 | WSL2 |
| 컨테이너 | Docker Desktop | 4.89.0 (Engine 29.7.2, Compose v5.5.0) | 필수 | Compose v2 이상 |
| 버전 관리 | Git for Windows | 2.55.0 | 필수 | - |
| 언어 | Python | 3.14.7 | 필수 | 3.12 이상(`pyproject.toml`) |
| 언어 | Node.js(npm) | 24.19.0 (npm 11.17.0) | 필수 | 22 이상(`web/package.json`) |
| GitHub | GitHub CLI(`gh`) | 2.102.0 | 권장 | PR 만들기·머지에 쓴다 |
| 패키지 설치 | winget | 1.29 | 권장 | 이 문서의 설치 명령에 쓴다 |
| 편집기 | VS Code | 1.145.3 | 선택 | 아무 편집기나 가능 |
| 브라우저 | Chrome | 최신 | 선택 | 제어판·Graylog 화면 |
| AI 도구 | Claude 데스크톱 앱(Claude Code) | 최신 | 선택 | 이전 PC처럼 AI와 함께 작업할 때 |
| 가상화 | VMware Workstation | 17.6.4 | 선택 | pfSense 로그 수집을 보여 줄 때만 |
| 방화벽 VM | pfSense CE | 2.7.2 | 선택 | 위와 같음 |

**최소 구성**(시연·S1~S12 실습에 충분): WSL2 + Docker Desktop + Git + Python + Node.js. 나머지는 편의·선택이다.

---

## 1. 시작 전 확인: 사양·가상화·관리자 권한

1. **RAM**: 설정 → 시스템 → 정보 → "설치된 RAM"이 16GB 이상인지 본다.
2. **가상화**: 작업 관리자(Ctrl+Shift+Esc) → 성능 → CPU → 오른쪽 아래 **"가상화: 사용"**인지 본다.
   - "사용 안 함"이면 BIOS/UEFI에서 켜야 한다. PC를 다시 시작하며 F2·Del 등으로 들어가 **Intel VT-x**(또는
     Intel Virtualization Technology) / **AMD SVM**을 Enabled로 바꾼다. 메뉴 이름은 PC마다 다르다. 이 설정은
     **직접** 한다.
3. **관리자 권한**: 3·4절의 일부 명령은 관리자 권한이 필요하다. 설치 중 "이 앱이 디바이스를 변경하도록
   허용하시겠어요?" 창이 뜨면 **예**를 누른다.
4. **디스크**: C 드라이브 여유 40GB 이상(Docker 이미지·데이터, 프로젝트, 각종 설치 파일).

---

## 2. Windows 업데이트와 winget

1. 설정 → Windows 업데이트 → **업데이트 확인**을 눌러 전부 설치하고 재시작한다. 업데이트를 해야 WSL·winget이
   제대로 동작한다.
2. **PowerShell**을 연다(시작 메뉴에서 "PowerShell" 검색). winget이 있는지 본다:

   ```powershell
   winget --version
   ```

   - 버전이 나오면 OK.
   - "인식되지 않습니다"가 나오면 **Microsoft Store**를 열고 **"앱 설치 관리자(App Installer)"**를 검색해
     설치·업데이트한 뒤 PowerShell을 새로 연다.
3. 처음 `winget`을 쓰면 원본 약관 동의(`Y`)를 묻는다. 내용을 읽고 동의하면 된다.

---

## 3. WSL2 켜기(Docker에 필요)

Docker Desktop은 WSL2(Windows 안의 리눅스 계층) 위에서 컨테이너를 돌린다.

1. 시작 메뉴에서 "PowerShell"을 **오른쪽 클릭 → 관리자 권한으로 실행**.
2. 아래를 실행한다(리눅스 배포판은 설치하지 않고 WSL만 켠다):

   ```powershell
   wsl --install --no-distribution
   ```

3. 끝나면 **PC를 다시 시작**한다.
4. 다시 켠 뒤 일반 PowerShell에서 확인:

   ```powershell
   wsl --version
   ```

   `WSL 버전: 2.x`가 나오면 OK. 오래된 버전이면 `wsl --update`.

---

## 4. 개발 도구 설치

일반 PowerShell에서 하나씩 실행한다. 각각 몇 분씩 걸릴 수 있다. 이미 설치된 것은 건너뛴다.

**Git**

```powershell
winget install --id Git.Git -e
```

**Python 3.14**: PATH 자동 등록 옵션을 함께 넘긴다(빼면 `python` 명령을 못 찾는 경우가 많다).

```powershell
winget install --id Python.Python.3.14 -e --override "/quiet InstallAllUsers=0 PrependPath=1 Include_launcher=1"
```

**Node.js LTS**(npm 포함)

```powershell
winget install --id OpenJS.NodeJS.LTS -e
```

**Docker Desktop**

```powershell
winget install --id Docker.DockerDesktop -e
```

**GitHub CLI**

```powershell
winget install --id GitHub.cli -e
```

> `winget`이 "패키지를 찾을 수 없음"을 내면 공식 사이트에서 받아 설치해도 된다(git-scm.com, python.org,
> nodejs.org, docker.com, cli.github.com). Python은 설치 첫 화면에서 **"Add python.exe to PATH"를 꼭 체크**한다.

**모두 설치했으면 PowerShell 창을 전부 닫고 새로 연다.** 새 창이어야 방금 설치한 명령을 찾는다. Docker Desktop
설치 뒤 재시작을 요구하면 재시작한다.

---

## 5. Docker Desktop 처음 설정

1. 시작 메뉴에서 **Docker Desktop**을 실행한다.
2. 약관(Docker Subscription Service Agreement) 화면이 나오면 내용을 읽고 동의한다. 개인 학습·소규모 용도는 무료다.
3. 로그인·설문은 **건너뛰어도(Skip)** 된다.
4. 설정(톱니바퀴) → General에서 **"Use the WSL 2 based engine"**이 켜져 있는지 본다(기본값).
5. 왼쪽 아래가 **"Engine running"**(초록)이 될 때까지 기다린다.
6. PowerShell에서 확인:

   ```powershell
   docker run --rm hello-world
   ```

   `Hello from Docker!`가 나오면 OK.

> Docker Desktop은 PC를 켤 때마다 직접 실행해야 한다. 자동으로 켜려면 설정 → General → "Start Docker Desktop
> when you sign in"을 켠다(선택).

---

## 6. Git·GitHub 설정

커밋에 남을 이름·이메일(GitHub 계정과 같게):

```powershell
git config --global user.name "shk12170-dev"
```

```powershell
git config --global user.email "<GitHub에 쓰는 이메일>"
```

GitHub CLI 로그인(PR 만들기·머지에 쓴다). 질문이 나오면 **GitHub.com → HTTPS → Yes(git 인증도 gh로) → Login with
a web browser**를 고르고, 화면의 코드를 브라우저에 입력한다:

```powershell
gh auth login
```

확인:

```powershell
gh auth status
```

> 줄바꿈 설정은 따로 건드리지 않는다. 저장소의 `.gitattributes`가 파일 종류별 줄바꿈을 정해 둔다.

---

## 7. 편집기·브라우저·Claude(작업 도구)

모두 선택이지만, 이전 PC와 같은 방식으로 작업하려면 설치한다.

**VS Code**(코드 편집기)

```powershell
winget install --id Microsoft.VisualStudioCode -e
```

VS Code를 열고 왼쪽 확장(Extensions)에서 **Python**(Microsoft)을 설치하면 코드 읽기·수정이 편하다.

**Chrome**

```powershell
winget install --id Google.Chrome -e
```

**Claude 데스크톱 앱**(Claude Code를 앱에서 쓰던 방식 그대로)

```powershell
winget install --id Anthropic.Claude -e
```

- 설치 뒤 앱을 열고 **본인 계정으로 직접 로그인**한다.
- 크롬에서 작업하려면 Chrome 웹 스토어에서 **Claude 확장 프로그램**을 설치하고 같은 계정으로 연결한다.
- `winget`에 없다고 나오면 claude.ai/download에서 받는다.

---

## 8. 최종 점검

새 PowerShell 창에서 아래 한 줄을 실행해 버전이 모두 나오는지 본다:

```powershell
git --version; python --version; node --version; npm --version; docker --version; docker compose version; gh --version; wsl --version
```

| 확인 | 기대하는 결과 |
| --- | --- |
| `python --version` | `Python 3.12` 이상(권장 3.14) |
| `node --version` | `v22` 이상 |
| `docker compose version` | `Docker Compose version v2` 이상 |
| `docker run --rm hello-world` | `Hello from Docker!` |
| `gh auth status` | `Logged in to github.com` |
| 작업 관리자 → 성능 → CPU | 가상화: 사용 |

전부 맞으면 개발 PC와 같은 기반이 준비됐다.

---

## 9. (선택) VMware와 pfSense VM

pfSense 방화벽 로그가 Graylog로 들어오는 장면까지 똑같이 하려면 필요하다. **S1~S12 실습·시연 트랙 A·B에는 필요 없다.**

개발 PC 구성: VMware Workstation 17.6.4, pfSense CE 2.7.2 VM, 가상 네트워크 **VMnet2**(호스트 전용, `172.16.50.0/24`),
pfSense `172.16.50.2`, 호스트(Windows) `172.16.50.100`.

1. **VMware Workstation 설치**: Broadcom 사이트에서 개인용 무료 버전을 받는다. Broadcom 계정 가입이 필요하다(직접 진행).
2. **가상 네트워크 만들기**: VMware → Edit → Virtual Network Editor → Change Settings(관리자) → Add Network →
   **VMnet2**, Host-only, Subnet IP `172.16.50.0`, Mask `255.255.255.0`, DHCP 끔 → Apply.
   그다음 Windows의 "VMware Network Adapter VMnet2" IPv4를 `172.16.50.100`/`255.255.255.0`으로 직접 정한다
   (설정 → 네트워크 → 고급 네트워크 설정 → 어댑터 옵션).
3. **pfSense VM 가져오기**(가장 쉬운 방법): 이전 PC의 VM 폴더(`.vmx`가 있는 폴더)를 통째로 USB 등으로 복사해
   새 PC에서 File → Open으로 연다. 처음 켤 때 묻는 창에서 **"I Moved It"**을 고른다(네트워크 설정이 유지된다).
   새로 설치한다면 pfSense CE 2.7.2 설치 이미지로 VM을 만들고 LAN을 VMnet2(`172.16.50.2`)에 둔다.
4. **pfSense 원격 로그**: pfSense 웹 → Status → System Logs → Settings → Remote Logging에서 서버를
   `172.16.50.100:1514`로 정한다.
5. **Windows 방화벽**: 인바운드 UDP 1514를 랩 대역(`172.16.50.0/24`)만 허용하는 규칙을 **직접** 만든다.
6. 저장소의 `.env`에서 `NB_SYSLOG_BIND=172.16.50.100`으로 바꾸면 `setup.ps1`이 중계기를 자동으로 띄운다.
   확인 방법은 README "pfSense 방화벽 로그 수집"을 본다.

---

## 10. 다음 단계

환경 준비가 끝났다. 이제 [NEW-PC.md](NEW-PC.md) **2절(저장소 받기)**부터 이어서 한다.

```
2. 저장소 받기 → 3. setup.ps1 -Live → 5. 서버 띄우기 → 6. 확인 → 7. 하던 작업 이어 가기
```

---

## 11. 막혔을 때

| 증상 | 해결 |
| --- | --- |
| `winget`을 찾을 수 없음 | Microsoft Store → "앱 설치 관리자" 설치·업데이트 → PowerShell 새로 열기 |
| `wsl --install`이 "가상화를 사용하도록 설정하세요" | 1절의 BIOS 가상화 켜기. Windows 기능에서 "가상 머신 플랫폼"이 켜져 있는지도 본다 |
| Docker Desktop이 "WSL 2 installation is incomplete" | 관리자 PowerShell에서 `wsl --update` → 재시작 |
| Docker Desktop이 계속 "Starting..." | Docker Desktop 종료 → `wsl --shutdown` → Docker Desktop 다시 실행 |
| `python`을 치면 Microsoft Store가 열림 | 설정 → 앱 → 고급 앱 설정 → **앱 실행 별칭**에서 `python.exe`·`python3.exe` 두 개를 끈다. 그래도 안 되면 Python을 4절 명령으로 다시 설치 |
| `node`·`npm`·`gh`를 찾을 수 없음 | 설치 뒤 **새 PowerShell 창**을 연다. 그래도 안 되면 PC 재시작 |
| `.ps1 파일을 로드할 수 없습니다... 실행 정책` | 이 저장소 스크립트는 `powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1`처럼 실행한다(PC 설정은 그대로 둔다) |
| 메모리 부족으로 Graylog·OpenSearch가 자꾸 꺼짐 | 다른 프로그램을 끈다. Wazuh(`-WithWazuh`)는 S7을 할 때만 켠다. 그래도 부족하면 RAM 16GB 이상 PC를 쓴다 |
| VMware와 Docker를 같이 켜면 느림 | 정상이다(둘 다 가상화를 쓴다). pfSense가 필요 없을 땐 VMware를 끈다 |
