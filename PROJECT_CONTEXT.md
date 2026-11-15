# 🛡️ LISA (Local Intelligent Security Agent) - 프로젝트 마스터 컨텍스트 (PROJECT_CONTEXT)

> **안내:** 본 문서는 Windows와 macOS 간의 작업 인수인계 및 Antigravity 에이전트 간의 컨텍스트 동기화를 위한 핵심 설계 문서입니다.  
> 맥(macOS)에서 새 대화를 시작할 때 **"PROJECT_CONTEXT.md 읽고 이전 대화 맥락 그대로 이어서 작업해줘"**라고 요청하면, 에이전트가 모든 배경지식과 세부 설계를 즉시 완벽하게 파악합니다.

---

## 1. 프로젝트 정체성 및 비전 (Identity & Vision)

* **프로젝트명:** **LISA (Local Intelligent Security Agent)**
* **핵심 미션:** 외부 클라우드 전송 0% (Zero Cloud, 100% 프라이버시 보장), 내 기기(PC/모바일) 내부에서 자율적으로 돌아다니며 데이터 유출입(I/O, 네트워크, 다운로드, 하드웨어)을 0.001초 만에 감시하고 이상 징후를 로컬 AI가 정밀 분석하여 맞대응하는 **온디바이스 지능형 사이버 가디언**.
* **타겟 사용자:** 단순 암호 같은 에러코드를 뱉는 기존 백신에 지치고, 일상에서 빈번하게 발생하는 인포스틸러(비밀번호 탈취), 클리퍼(계좌/지갑 바꿔치기), 도둑 채굴기, 스미싱/보이스피싱, 피싱 웹 링크에 노출된 일반 사용자 및 보안 전문가.

---

## 2. 기존 보안 도구/API 대비 LISA의 압도적 차별점 (Why LISA?)

1. **껍데기가 아닌 "실제 페이로드/데이터 의미론적 분석 (Semantic Payload Understanding)":**
   - 기존 방화벽/DLP는 포트 번호, 파일명, 정상 JSON 껍데기만 보고 통과시킴.
   - LISA는 빠져나가는(Outbound) 데이터나 유입되는(Inbound) 바이트를 뜯어보고, *"겉은 앱 오류 보고서인데 속은 크롬 세션 쿠키/토큰 탈취 페이로드네?"*라는 실제 의미와 의도를 간파.
2. **사전 추론 (Predictive AI) vs 사후 대조 (Signature DB):**
   - 시티즌코난, 후후, 더치트, 기존 백신은 "이미 피해자가 신고한 DB"에 없으면 신종 사기/악성코드를 100% 놓침.
   - LISA의 로컬 AI는 최초 발생한 제로데이 변종이어도 문맥/바이너리 엔트로피/이상 I/O 행위를 실시간 추론하여 차단.
3. **100% 로컬 온디바이스 (Zero-Cloud, 비용 0원, 프라이버시 100%):**
   - 민감한 개인 파일, 계좌 정보, 통화/문자 내용이 외부 빅테크 클라우드로 단 1바이트도 전송되지 않음.
   - 오프라인/비행기 모드에서도 정상 구동.
4. **초등학생도 이해하는 자연어 진단서 (Explainable Security):**
   - `Win32/Trojan.Generic.0x80070002` 같은 외계어가 아닌, **"이 파일은 사진으로 위장했으나 크롬 비밀번호를 빼돌리려 합니다"**라는 명쾌한 다국어(한국어/English) 진단서 발급.

---

## 3. 핵심 5대 철벽 방어 매트릭스 (Threat Matrix)

1. **[다운로드 게이트 (File & Dropper Shield)]**
   - `Downloads` 및 악성코드 주요 은신처(`%TEMP%`, `C:\Users\Public`, `Startup`, Mac의 `~/Downloads`, `/tmp`) 멀티 감시.
   - **대용량 파일 0.001초 선빵 기술:**
     - 헤더/푸터 스파스 샘플링(앞/뒤 64KB만 찍어서 매직바이트 및 엔트로피 측정).
     - NTFS/APFS 포인터 이동(Atomic Rename)으로 10GB 파일도 1밀리초 만에 `quarantine/` 금고로 이동 격리.
     - 다운로드 완료 전 임시 파일(`.crdownload`, `.part`) 필터링.
2. **[하드웨어 게이트 (Hardware & USB Sentinel)]**
   - USB/외장 드라이브 연결 시 즉각 WMI/시스템 이벤트 포착 후 자동 전수 스캔.
   - 백그라운드 프로세스가 대량의 문서를 USB로 복사하는 비정상 I/O 시퀀스 차단.
3. **[링크 & 스미싱 게이트 (Phishing & Smishing Shield)]**
   - 가족 사칭("엄마 나 액정 깨짐"), 기관 사칭(검찰/금감원), 정부지원 대출 사칭 문자/링크를 로컬 AI가 문맥으로 즉각 판정.
4. **[금융 & 클립보드 게이트 (Financial & Clipboard Shield)]**
   - 복사(`Ctrl+C`) 시 클립보드의 계좌번호/가상화폐 지갑 주소를 해커 주소로 슬쩍 바꾸는 클리퍼(Clipper) 악성코드 즉시 사살 및 원본 주소 복원.
5. **[와이파이 게이트 (Wi-Fi & Network Guardian)]**
   - 비밀번호 없는 취약한 오픈 와이파이(Open Wi-Fi), 사악한 쌍둥이(Evil Twin) 가짜 공유기 경고.
   - 악성 DNS 변조(파밍) 징후 실시간 탐지.

---

## 4. 2단계 하이브리드 파이프라인 (초고속 필터 + 로컬 AI 부검)

```
[데이터 유입/유출 감지 (파일, 패킷, 클립보드)]
        │
        ▼ (모든 데이터 전수 검사: CPU 부하 0% 수준)
┌────────────────────────────────────────────────────────┐
│ [Layer 1] 0.001초 결정적 초고속 필터 (Fast Filter)     │
│ - 매직 바이트 vs 확장자 교차 검증 (PDF/JPG 위장 EXE)   │
│ - 섀넌 엔트로피 (Shannon Entropy > 7.2 패킹/암호화 탐지)│
│ - 민감 시크릿 정규식 (API Key, JWT, .env, Private Key) │
│ - 파워쉘 -enc, IEX, 리버스 쉘 시그니처                 │
└────────────────────────────────────────────────────────┘
        │
        ├─ [SAFE] ───────────────► 무지연 통과 및 백그라운드 로깅
        │
        └─ [SUSPICIOUS / HIGH_RISK]
                   │ (1밀리초 선빵: 파일 확장자 .quarantine 강제 변경 + 격리)
                   ▼
┌────────────────────────────────────────────────────────┐
│ [Layer 2] 로컬 AI 정밀 부검 (Local LLM Verifier)       │
│ - 초경량 모델: Qwen 2.5-Coder (1.5B) 또는 Llama 3.2    │
│ - Zero-Cloud: Ollama(11434) / llama.cpp(8080) 연동     │
│ - 엄격한 JSON 스키마 강제 출력 (risk_score, threat_type)│
│ - 다국어 진단서 생성: 한국어 (기본) / English 토글      │
│ - Fallback 내장: LLM 미실행 시 1단계 점수로 즉각 대체  │
└────────────────────────────────────────────────────────┘
```

---

## 5. 크로스 플랫폼 & 모바일 구현 로드맵

| 플랫폼 | 구현 가능도 | 핵심 구현 방식 |
| :--- | :---: | :--- |
| **Windows** | **100%** | Python `watchdog`, Win32 API, 윈도우 토스트 푸시 알림, FastAPI + WebSockets |
| **macOS** | **100%** | `pathlib`, AppleScript 알림(`osascript`), `/tmp` & `~/Downloads` 멀티 감시 |
| **Android** | **85~90%** | `NotificationListenerService`(문자/카톡 가로채기), `FileObserver`(다운로드 APK 감시), `VpnService`(로컬 DNS/웹 트래픽 차단) |
| **iOS** | **55~60%** | `SMS Filter Extension`(스미싱 문자 격리), `Network Extension`(로컬 웹/DNS 피싱 차단), `Safari Extension` |

---

## 6. 프로젝트 파일 구조 (예정)

```text
Local AI Security/
├── PROJECT_CONTEXT.md         # [본 문서] 맥/윈도우 크로스플랫폼 인수인계 마스터 문서
├── .gitignore                 # venv, __pycache__, 격리소 파일 제외 설정
├── lisa_core/
│   ├── static_scanner.py      # [1단계] 0.001초 초고속 정적 분석 (매직바이트, 엔트로피, 대용량 스파스 샘플러)
│   ├── ai_brain.py            # [2단계] 로컬 LLM 부검 엔진 (Ollama/llama.cpp, 다국어 진단서, Fallback)
│   ├── file_watcher.py        # 크로스 플랫폼 멀티 경로 실시간 감시 (Win/Mac 자동 감지)
│   ├── fraud_shield.py        # 스미싱/피싱 문자, 클립보드 계좌 변조, 와이파이 진단 모듈
│   └── notifier.py            # OS 네이티브 푸시 알림 (Win Toast & Mac Notification Center)
├── templates/
│   └── index.html             # LISA 다크모드 관제 센터 UI (언어 선택, Hex 뷰어, 실시간 스트림)
├── server.py                  # FastAPI 백엔드 + WebSocket 실시간 순찰 스트림
├── safe_simulator.py          # 안전한 모의 공격 5종 테스트 스위트 (위장 EXE, 스미싱, 클립보드 변조)
├── requirements.txt           # 의존성 패키지 목록
└── README.md                  # 실행 가이드 (PowerShell 및 Bash)
```

---

## 7. 맥(macOS)에서 이어서 작업할 때 프롬프트 예시

맥에서 Antigravity를 켜고 이 프로젝트 폴더를 열었을 때 아래와 같이 입력하시면 됩니다:
```text
PROJECT_CONTEXT.md 파일을 확인했습니다. 
이 문서에 정의된 LISA의 아키텍처와 설계를 바탕으로 [작업할 내용]을 이어서 진행해 주세요.
```
