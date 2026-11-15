"""
LISA AI Brain (Layer 2: Local LLM Deep Autopsy Engine)
- Zero-Cloud: 오직 로컬 머신 내부(Ollama 또는 llama.cpp)에서만 실행
- 엄격한 JSON Schema 강제 출력 (환각 방지)
- 다국어 진단서 지원 (한국어 / English 토글)
- 스마트 Fallback 내장: 로컬 LLM이 오프라인이어도 시스템 중단 없이 1단계 결과 기반 합성 보고서 발행
"""

import json
import time
import requests
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from .static_scanner import ScanResult


class AIAnalysisReport(BaseModel):
    """2단계 로컬 AI 부검 보고서 모델"""
    risk_score: int = Field(description="최종 정밀 위험도 (1~10점)")
    threat_category: str = Field(description="위협 유형 (예: 위장_실행파일, 인포스틸러_의심, 정상 등)")
    concise_explanation: str = Field(description="초등학생도 이해할 수 있는 1~2문장의 명확한 자연어 해설")
    recommended_action: str = Field(description="권고 조치: 허용(ALLOW), 격리_유지(QUARANTINE), 영구삭제(DELETE)")
    language: str = Field(default="ko", description="보고서 언어 (ko/en)")
    is_fallback: bool = Field(default=False, description="로컬 LLM 오프라인으로 인한 Fallback 보고서 여부")
    latency_ms: float = Field(description="AI 추론 소요 시간 (밀리초)")
    model_name: str = Field(description="사용된 로컬 모델명")


class AIBrain:
    """플랫폼 독립적 로컬 LLM 심층 정밀 부검 엔진"""

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434/api/generate",
        llama_cpp_url: str = "http://localhost:8080/v1/chat/completions",
        model_name: str = "qwen2.5-coder:1.5b",
        timeout_seconds: float = 8.0,
        language: str = "ko"
    ):
        self.ollama_url = ollama_url
        self.llama_cpp_url = llama_cpp_url
        self.model_name = model_name
        self.timeout = timeout_seconds
        self.language = language

    def check_llm_status(self) -> Dict[str, Any]:
        """로컬 LLM 엔드포인트 헬스체크"""
        # 1. Ollama 헬스체크
        try:
            res = requests.get("http://localhost:11434/api/tags", timeout=1.0)
            if res.status_code == 200:
                models = [m.get("name") for m in res.json().get("models", [])]
                return {"online": True, "provider": "Ollama", "models": models}
        except Exception:
            pass

        # 2. llama.cpp 헬스체크
        try:
            res = requests.get("http://localhost:8080/health", timeout=1.0)
            if res.status_code == 200:
                return {"online": True, "provider": "llama.cpp", "models": [self.model_name]}
        except Exception:
            pass

        return {"online": False, "provider": "None (Using Smart Fallback)", "models": []}

    def _build_prompt(self, scan_result: ScanResult, snippet: str, lang: str) -> str:
        """엄격한 JSON 스키마 유도를 위한 프롬프트 생성"""
        if lang == "en":
            return f"""You are LISA (Local Intelligent Security Agent), a Chief Incident Response Investigator.
Analyze the following quarantined file metadata and extracted byte strings.
Return ONLY a valid JSON object matching the requested schema. No extra text or markdown formatting.

[Scan Context]
- Claimed Extension: {scan_result.claimed_ext}
- Actual Magic Mime: {scan_result.detected_mime}
- Shannon Entropy: {scan_result.entropy} / 8.0
- Extension Mismatched: {scan_result.is_extension_mismatched}
- 1st Layer Reasons: {", ".join(scan_result.reasons) if scan_result.reasons else "None"}
- Matched Signatures: {", ".join(scan_result.matched_patterns) if scan_result.matched_patterns else "None"}

[Extracted Strings / Byte Snippet]
{snippet[:1500] if snippet else "(No readable strings extracted)"}

[JSON Schema Requirement]
{{
  "risk_score": <int 1 to 10>,
  "threat_category": "<CLEAN | MASQUERADED_EXECUTABLE | INFOSTEALER_SUSPECT | RANSOMWARE_SUSPECT | OBFUSCATED_SCRIPT | DATA_EXFILTRATION>",
  "concise_explanation": "<1-2 sentence clear plain English explanation of the threat and intent>",
  "recommended_action": "<ALLOW | QUARANTINE | DELETE>"
}}
"""
        else:
            return f"""당신은 온디바이스 지능형 사이버 보안관 LISA(Local Intelligent Security Agent)입니다.
아래 격리된 파일의 메타데이터와 추출된 코드/문자열 조각을 바탕으로 정밀 부검을 수행하세요.
마크다운 코드블록이나 불필요한 설명 없이, 오직 아래 명시된 순수 JSON 객체 하나만 출력하세요.

[1단계 스캔 정보]
- 기재된 파일 확장자: {scan_result.claimed_ext}
- 실제 매직 바이트 형식: {scan_result.detected_mime}
- 측정된 섀넌 엔트로피: {scan_result.entropy} / 8.0
- 확장자 위장 여부: {scan_result.is_extension_mismatched}
- 감지된 위험 사유: {", ".join(scan_result.reasons) if scan_result.reasons else "없음"}
- 매칭된 악성 시그니처: {", ".join(scan_result.matched_patterns) if scan_result.matched_patterns else "없음"}

[추출된 내부 문자열/바이너리 조각]
{snippet[:1500] if snippet else "(추출된 가독 텍스트 없음)"}

[JSON 출력 형식 요구사항]
{{
  "risk_score": <1부터 10까지의 정수 위험도>,
  "threat_category": "<정상 | 위장_실행파일 | 인포스틸러_의심 | 랜섬웨어_의심 | 난독화_스크립트 | 데이터_유출>",
  "concise_explanation": "<이 파일이 왜 위험한지, 어떤 악성 의도를 가지고 있는지 초등학생도 이해할 수 있는 1~2문장의 명확한 한국어 해설>",
  "recommended_action": "<허용 | 격리_유지 | 영구삭제>"
}}
"""

    def analyze(
        self,
        scan_result: ScanResult,
        raw_snippet: Optional[str] = None,
        language_override: Optional[str] = None
    ) -> AIAnalysisReport:
        """
        로컬 LLM 정밀 부검 실행 (Ollama -> Fallback 파이프라인)
        """
        start_time = time.perf_counter()
        lang = language_override or self.language
        snippet = raw_snippet or scan_result.sample_text_snippet or ""
        prompt = self._build_prompt(scan_result, snippet, lang)

        # 1. Ollama 호출 시도
        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.1,
                    "num_predict": 300
                }
            }
            res = requests.post(self.ollama_url, json=payload, timeout=self.timeout)
            if res.status_code == 200:
                raw_response = res.json().get("response", "")
                parsed = json.loads(raw_response)
                latency = round((time.perf_counter() - start_time) * 1000, 2)
                return AIAnalysisReport(
                    risk_score=int(parsed.get("risk_score", scan_result.risk_score)),
                    threat_category=str(parsed.get("threat_category", "분석완료")),
                    concise_explanation=str(parsed.get("concise_explanation", "로컬 AI 부검 완료")),
                    recommended_action=str(parsed.get("recommended_action", "격리_유지")),
                    language=lang,
                    is_fallback=False,
                    latency_ms=latency,
                    model_name=self.model_name,
                )
        except Exception:
            pass  # Fallback으로 우아하게 이동

        # 2. 로컬 LLM이 오프라인일 때의 스마트 Fallback 보고서
        latency = round((time.perf_counter() - start_time) * 1000, 2)
        return self._generate_fallback_report(scan_result, lang, latency)

    def _generate_fallback_report(self, scan_result: ScanResult, lang: str, latency: float) -> AIAnalysisReport:
        """로컬 LLM 오프라인 시 1단계 분석 결과를 조합하여 안정적인 보고서 생성"""
        score = scan_result.risk_score

        if lang == "en":
            if scan_result.is_extension_mismatched:
                category = "MASQUERADED_EXECUTABLE"
                expl = f"Critical risk: Masqueraded file attempting execution disguised as '{scan_result.claimed_ext}' but containing a Windows/Linux binary ({scan_result.detected_mime})."
                action = "DELETE"
            elif scan_result.matched_patterns:
                category = "MALICIOUS_SCRIPT_OR_STEALER"
                expl = f"Suspicious behavior detected: Matched signatures ({', '.join(scan_result.matched_patterns[:2])})."
                action = "QUARANTINE"
            elif scan_result.entropy > 7.2:
                category = "HIGH_ENTROPY_PACKED"
                expl = f"High entropy payload ({scan_result.entropy} > 7.2) indicating heavy packing or encryption."
                action = "QUARANTINE"
            else:
                category = "CLEAN"
                expl = "No anomalous structures or suspicious code signatures detected."
                action = "ALLOW"
        else:
            if scan_result.is_extension_mismatched:
                category = "위장_실행파일"
                expl = f"치명적 위험: 겉으로는 '{scan_result.claimed_ext}' 파일인 척 위장하고 있으나, 내부는 실행 가능한 바이너리({scan_result.detected_mime})입니다."
                action = "영구삭제"
            elif scan_result.matched_patterns:
                category = "악성_스크립트_또는_탈취시도"
                expl = f"의심 행위 포착: 주요 위협 시그니처({', '.join(scan_result.matched_patterns[:2])})가 발견되었습니다."
                action = "격리_유지"
            elif scan_result.entropy > 7.2:
                category = "고엔트로피_패킹의심"
                expl = f"비정상적인 고엔트로피({scan_result.entropy} > 7.2)가 감지되어 패킹이나 난독화된 악성 페이로드로 의심됩니다."
                action = "격리_유지"
            else:
                category = "정상"
                expl = "구조적 이상점이나 알려진 악성 시그니처가 발견되지 않은 정상 파일입니다."
                action = "허용"

        return AIAnalysisReport(
            risk_score=score,
            threat_category=category,
            concise_explanation=f"[LISA 지능형 폴백] {expl}",
            recommended_action=action,
            language=lang,
            is_fallback=True,
            latency_ms=latency,
            model_name="LISA-Heuristic-Fallback",
        )
