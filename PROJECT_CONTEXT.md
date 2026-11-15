# 🛡️ LISA (Local Intelligent Security Agent) - 프로젝트 마스터 컨텍스트 (PROJECT_CONTEXT)

> **안내:** 본 문서는 Windows, macOS, 모바일 간의 작업 인수인계 및 Antigravity 에이전트 간의 컨텍스트 동기화를 위한 핵심 설계 문서입니다.  
> 맥(macOS)에서 새 대화를 시작할 때 **"PROJECT_CONTEXT.md 읽고 이전 대화 맥락 그대로 이어서 작업해줘"**라고 요청하면, 에이전트가 모든 배경지식과 세부 설계를 즉시 완벽하게 파악합니다.

---

## 1. 프로젝트 정체성 및 비전 (Identity & Vision)

* **프로젝트명:** **LISA (Local Intelligent Security Agent)**
* **핵심 미션:** 외부 클라우드 전송 0% (Zero Cloud, 100% 프라이버시 보장), 내 기기(PC/모바일) 내부에서 자율적으로 돌아다니며 데이터 유출입(I/O, 네트워크, 다운로드, 하드웨어)을 0.001초 만에 감시하고 이상 징후를 로컬 AI가 정밀 분석하여 맞대응하는 **온디바이스 지능형 사이버 가디언**.
* **타겟 사용자:** 단순 암호 같은 에러코드를 뱉는 기존 백신에 지치고, 일상에서 빈번하게 발생하는 인포스틸러(비밀번호 탈취), 클리퍼(계좌/지갑 바꿔치기), 도둑 채굴기, 스미싱/보이스피싱, 피싱 웹 링크에 노출된 일반 사용자 및 보안 전문가.

---

## 2. 지원 OS 및 플랫폼 버전 타겟팅

글로벌 보안 업계 표준인 현역 OS를 1차 타겟으로 완벽 지원합니다:
* **Windows:** **Windows 10 & 11** (전 세계 PC 점유율 95% 이상 지원)
* **macOS:** **macOS 12(Monterey) ~ 최신 macOS 15(Sequoia)** (Apple Silicon M1/M2/M3/M4 및 Intel Mac 지원)
* **Android:** **Android 10 이상 ~ 14/15** (삼성 갤럭시, 구글 픽셀 등 전 기종)
* **iOS:** **iOS 16 이상 ~ 18** (아이폰 8 이후 전 기종)

---

## 3. 핵심 5대 철벽 방어 매트릭스 (Threat Matrix)

1. **[다운로드 게이트 (File & Dropper Shield)]**
   - `Downloads` 및 악성코드 주요 은신처(`%TEMP%`, `C:\Users\Public`, `Startup`, Mac의 `~/Downloads`, `/tmp`) 멀티 감시.
   - **대용량 파일 0.001초 선빵 기술:**
     - 헤더/푸터 스파스 샘플링(앞/뒤 64KB만 찍어서 매직바이트 및 엔트로피 측정).
     - NTFS/APFS 포인터 이동(Atomic Rename)으로 10GB 파일도 1밀리초 만에 `quarantine_vault/` 금고로 이동 격리.
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

## 4. 아키텍처: 코어-어댑터(Core-Adapter) 패턴 & 현재 구현 상태

두뇌(Core)는 딱 하나만 만들고, 각 OS에 맞는 센서(Adapter)만 갈아 끼우는 클린 아키텍처입니다:

```text
LISA/
├── PROJECT_CONTEXT.md          # 맥/윈도우 인수인계 마스터 문서 [최신 업데이트]
├── .gitignore                  # venv, 격리소, 임시파일 차단 [완료]
├── requirements.txt            # 파이썬 의존성 패키지 명세 [완료]
│
├── core/                       # 🧠 [100% 공통 두뇌 - 구현 및 단위테스트 100% 통과!]
│   ├── __init__.py             # 코어 패키지 엔트리포인트 [완료]
│   ├── static_scanner.py       # 0.001초 선빵 필터 (매직바이트, 엔트로피, 정규식, 대용량 스파스) [완료]
│   ├── ai_brain.py             # 로컬 AI 부검 엔진 (Ollama/llama.cpp, 다국어 진단서, Fallback) [완료]
│   └── fraud_rules.py          # 보이스피싱/스미싱/계좌 사기/와이파이 패턴 분석 로직 [완료]
│
├── adapters/                   # 🔌 [OS별 감시 센서 & 푸시 알림 플러그인 - 다음 단계]
│   ├── win_adapter.py          # 윈도우용 센서 (Downloads/%TEMP% 감시, 윈도우 토스트 알림)
│   ├── mac_adapter.py          # 맥용 센서 (~/Downloads 감시, 맥OS 알림센터 연동)
│   └── os_detector.py          # 현재 OS(Win/Mac)를 자동 감지하여 적절한 어댑터 연결
│
├── web_ui/                     # 💻 [공통 관제 대시보드 - 반응형 웹]
│   ├── server.py               # FastAPI 백엔드 + WebSocket 실시간 스트림
│   └── templates/
│       └── index.html          # PC 모니터 + 스마트폰 모바일 화면을 동시 지원하는 반응형 UI
│
├── tests/                      # 🧪 [안전한 모의 침투 실험실]
│   └── safe_simulator.py       # 5가지 모의 공격 안전 투하 스크립트
│
└── mobile_bridge/              # 📱 [모바일 확장 명세]
    ├── android_spec.md         # 안드로이드 백그라운드 리스너 연동 가이드 (구현율 ~90%)
    └── ios_spec.md             # iOS SMS/네트워크 익스텐션 연동 가이드 (구현율 ~60%)
```

### ✅ 구현 완료 현황 (Milestone Status)
- [x] **Core 1: `core/static_scanner.py`** (0.001초 초고속 정적 스캐너, 매직바이트 위장 탐지, 고속 섀넌 엔트로피, 대용량 파일 스파스 샘플러)
- [x] **Core 2: `core/ai_brain.py`** (로컬 LLM JSON 스키마 강제, 다국어 한국어/영어 진단서, 스마트 오프라인 Fallback 엔진)
- [x] **Core 3: `core/fraud_rules.py`** (스미싱 5대 카테고리 문맥 탐지, 클립보드 가상화폐/계좌 하이재킹 차단, 공용 와이파이 위험도 진단)
- [x] **단위 테스트:** 위장 실행파일, AI 진단서, 스미싱 탐지, 클리퍼 가로채기 4종 테스트 **100% 통과**

---

## 5. 맥(macOS)에서 이어서 작업할 때 프롬프트 예시

맥에서 Antigravity를 켜고 이 프로젝트 폴더를 열었을 때 아래와 같이 입력하시면 됩니다:
```text
PROJECT_CONTEXT.md 파일을 확인했습니다. 
현재 core/ 엔진 3종 구현 및 테스트가 완료된 상태입니다.
다음 단계인 adapters/ (OS별 감시 센서 및 푸시 알림) 및 web_ui/ 작업을 이어서 진행해 주세요.
```
