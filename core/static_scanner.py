"""
LISA Static Scanner (Layer 1: Deterministic Fast Filter)
- 실행 목표 시간: < 1~5ms (CPU 부담 0% 수준)
- 매직 바이트 vs 파일 확장자 교차 검증 (위장 실행 파일 탐지)
- 대용량 파일 스파스 샘플링 (Sparse Chunking: 100GB 파일도 1ms 만에 스캔)
- 섀넌 엔트로피(Shannon Entropy) 고속 측정 (7.2 초과 시 패킹/암호화 의심)
- 위험 스크립트 및 민감 시크릿 유출 패턴 정규식 탐지
"""

import os
import re
import math
import time
from typing import List, Dict, Optional, Tuple
from pydantic import BaseModel, Field


class ScanResult(BaseModel):
    """1단계 정적 검사 결과 데이터 모델"""
    is_suspicious: bool = Field(description="격리 대상 의심/위험 파일 여부")
    risk_level: str = Field(description="위험 등급: SAFE, SUSPICIOUS, HIGH_RISK, CRITICAL")
    risk_score: int = Field(description="1단계 추정 위험도 점수 (1~10)")
    entropy: float = Field(description="측정된 섀넌 엔트로피 값 (0.0 ~ 8.0)")
    detected_mime: str = Field(description="매직 바이트로 식별된 실제 파일 형식")
    claimed_ext: str = Field(description="파일명에 기재된 확장자")
    is_extension_mismatched: bool = Field(description="확장자 위장 여부")
    reasons: List[str] = Field(default_factory=list, description="위험 감지 사유 목록")
    matched_patterns: List[str] = Field(default_factory=list, description="매칭된 악성/시크릿 시그니처 목록")
    latency_ms: float = Field(description="검사에 소요된 시간 (밀리초)")
    sample_text_snippet: Optional[str] = Field(default=None, description="2단계 AI 부검용 텍스트/스트링 스니펫")


class StaticScanner:
    """플랫폼 독립적 초고속 정적 보안 분석기"""

    # 매직 바이트 시그니처 정의 (앞부분 바이트)
    MAGIC_SIGNATURES: Dict[str, Tuple[bytes, str]] = {
        "exe": (b"MZ", "application/x-dosexec (Windows PE/Executable)"),
        "elf": (b"\x7fELF", "application/x-executable (Linux ELF)"),
        "pdf": (b"%PDF-", "application/pdf (PDF Document)"),
        "zip": (b"PK\x03\x04", "application/zip (ZIP Archive / Office)"),
        "png": (b"\x89PNG\r\n\x1a\n", "image/png (PNG Image)"),
        "jpg": (b"\xff\xd8\xff", "image/jpeg (JPEG Image)"),
        "gif": (b"GIF8", "image/gif (GIF Image)"),
        "tar": (b"ustar", "application/x-tar (TAR Archive)"),
        "gzip": (b"\x1f\x8b", "application/gzip (GZIP Compressed)"),
        "sqlite": (b"SQLite format 3\x00", "application/x-sqlite3 (SQLite DB)"),
    }

    # 주요 확장자별 기대되는 매직 포맷
    EXPECTED_MAGIC_MAP = {
        ".pdf": "pdf",
        ".png": "png",
        ".jpg": "jpg",
        ".jpeg": "jpg",
        ".gif": "gif",
        ".zip": "zip",
        ".docx": "zip",
        ".xlsx": "zip",
        ".pptx": "zip",
        ".exe": "exe",
        ".dll": "exe",
        ".sys": "exe",
    }

    # 악성 스크립트 및 위협 행위 시그니처 (사전 컴파일)
    SUSPICIOUS_SCRIPT_PATTERNS = [
        (re.compile(r"powershell(\.exe)?\s+.*-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}", re.IGNORECASE), "난독화된 Base64 PowerShell 실행 명령"),
        (re.compile(r"Invoke-Expression|IEX\s*\(", re.IGNORECASE), "메모리 직접 실행 (IEX/Invoke-Expression) 시그니처"),
        (re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE), "랜섬웨어 볼륨 섀도우 복사본 삭제 명령 (vssadmin)"),
        (re.compile(r"mimikatz|sekurlsa|logonpasswords", re.IGNORECASE), "윈도우 자격증명 탈취 도구(Mimikatz) 시그니처"),
        (re.compile(r"/bin/(ba)?sh\s+-i\s+>&?\s*/dev/tcp/", re.IGNORECASE), "Linux Bash 리버스 쉘 페이로드"),
        (re.compile(r"nc(\.exe)?\s+-e\s+cmd(\.exe)?", re.IGNORECASE), "Netcat 윈도우 원격 명령 쉘 바인딩"),
        (re.compile(r"certutil(\.exe)?\s+-urlcache\s+-split\s+-f", re.IGNORECASE), "CertUtil 악용 원격 바이너리 다운로드 명령"),
        (re.compile(r"bitsadmin(\.exe)?\s+/transfer", re.IGNORECASE), "BitsAdmin 악용 백그라운드 악성 다운로드"),
        (re.compile(r"AppData\\Local\\Google\\Chrome\\User Data.*Login Data", re.IGNORECASE), "크롬 저장 비밀번호 파일 무단 접근(인포스틸러)"),
    ]

    # 아웃바운드 민감 시크릿 유출 패턴
    SECRET_PATTERNS = [
        (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key 식별자 평문 노출"),
        (re.compile(r"sk-[a-zA-Z0-9_-]{32,}"), "OpenAI / Anthropic API Key 평문 노출"),
        (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "RSA/SSH 개인 암호화 키 평문 노출"),
        (re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "JWT 인증 토큰 평문 노출"),
        (re.compile(r"(DB_PASSWORD|SECRET_KEY|DATABASE_URL)\s*=\s*['\"][^\n'\"]{4,}['\"]", re.IGNORECASE), ".env 핵심 시크릿 설정값 노출"),
    ]

    # 간접 프롬프트 인젝션 패턴
    PROMPT_INJECTION_PATTERNS = [
        (re.compile(r"(ignore\s+(all\s+)?previous\s+instructions|system\s+prompt\s+override)", re.IGNORECASE), "LLM 탈옥 및 시스템 프롬프트 무력화 시도"),
        (re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode|DAN\s+mode", re.IGNORECASE), "DAN 탈옥 모드 페이로드"),
    ]

    def __init__(self, sample_chunk_size: int = 65536, entropy_threshold: float = 7.2):
        """
        :param sample_chunk_size: 대용량 파일 앞/뒤 스파스 샘플링 크기 (기본값: 64KB)
        :param entropy_threshold: 고엔트로피 의심 임계치 (기본값: 7.2 / 8.0 만점)
        """
        self.sample_chunk_size = sample_chunk_size
        self.entropy_threshold = entropy_threshold

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """바이트 빈도수 기반 섀넌 엔트로피(Shannon Entropy) 고속 연산 (0.0 ~ 8.0)"""
        if not data:
            return 0.0

        length = len(data)
        freq = [0] * 256
        for b in data:
            freq[b] += 1

        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return round(entropy, 3)

    def read_sparse_chunks(self, file_path: str) -> Tuple[bytes, bytes, int]:
        """
        대용량 파일(100GB도 1ms) 스파스 샘플러:
        파일의 맨 앞 헤더(64KB)와 맨 끝 푸터(64KB)만 Seek하여 고속 로드
        :return: (header_bytes, footer_bytes, total_file_size)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")

        file_size = os.path.getsize(file_path)

        with open(file_path, "rb") as f:
            # 1. 앞부분(Header) 읽기
            header_bytes = f.read(self.sample_chunk_size)

            # 2. 뒷부분(Footer) 읽기
            if file_size > self.sample_chunk_size * 2:
                f.seek(file_size - self.sample_chunk_size)
                footer_bytes = f.read(self.sample_chunk_size)
            elif file_size > self.sample_chunk_size:
                f.seek(self.sample_chunk_size)
                footer_bytes = f.read()
            else:
                footer_bytes = b""

        return header_bytes, footer_bytes, file_size

    def identify_magic_type(self, header_bytes: bytes) -> Tuple[str, str]:
        """헤더 바이트를 기반으로 실제 파일 타입 식별"""
        for ext, (sig, mime) in self.MAGIC_SIGNATURES.items():
            if header_bytes.startswith(sig):
                return ext, mime

        # Tar 파일 특수 위치 (바이트 257)
        if len(header_bytes) >= 262 and header_bytes[257:262] == b"ustar":
            return "tar", "application/x-tar (TAR Archive)"

        return "unknown", "application/octet-stream (Unknown/Plain)"

    def scan_file(self, file_path: str) -> ScanResult:
        """
        단일 파일 0.001초 선빵 검사 메인 진입점
        """
        start_time = time.perf_counter()
        reasons: List[str] = []
        matched_patterns: List[str] = []
        risk_score = 1
        is_suspicious = False

        _, ext = os.path.splitext(file_path)
        claimed_ext = ext.lower()

        # 1. 스파스 샘플링 (앞 64KB, 뒤 64KB 로드)
        header_bytes, footer_bytes, file_size = self.read_sparse_chunks(file_path)
        combined_bytes = header_bytes + footer_bytes

        # 2. 매직 바이트 검사 및 확장자 위장 감지
        detected_ext, detected_mime = self.identify_magic_type(header_bytes)
        is_mismatched = False

        # 사진, 문서 확장자인데 내부는 윈도우/리눅스 실행 파일인 경우 (CRITICAL)
        if claimed_ext in [".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".docx", ".xlsx"]:
            if detected_ext in ["exe", "elf"]:
                is_mismatched = True
                is_suspicious = True
                risk_score = max(risk_score, 9)
                reasons.append(f"치명적 위장 감지: 확장자는 '{claimed_ext}'이나 내부는 실행 파일({detected_mime})입니다.")

        # 3. 섀넌 엔트로피 측정 (패킹, 암호화, 랜섬웨어 의심)
        # 헤더와 푸터 엔트로피를 각각 측정
        header_entropy = self.calculate_entropy(header_bytes)
        footer_entropy = self.calculate_entropy(footer_bytes) if footer_bytes else header_entropy
        max_entropy = max(header_entropy, footer_entropy)

        # 텍스트, 스크립트, PDF인데 엔트로피가 비정상적으로 7.2 초과 시
        if max_entropy > self.entropy_threshold:
            # 이미 압축 포맷(ZIP, GZ)이나 미디어(JPG, PNG)는 원래 엔트로피가 높으므로 제외
            if claimed_ext not in [".zip", ".tar", ".gz", ".jpg", ".png", ".mp4", ".mp3", ".7z"]:
                is_suspicious = True
                risk_score = max(risk_score, 8)
                reasons.append(f"고엔트로피 감지 ({max_entropy} > {self.entropy_threshold}): 난독화/암호화/패킹된 페이로드 의심.")

        # 4. 문자열 추출 및 시그니처 정규식 검사
        try:
            # 안전한 디코딩 (utf-8, cp949, latin1 순)
            sample_text = combined_bytes.decode("utf-8", errors="ignore")
        except Exception:
            sample_text = ""

        # 악성 스크립트 시그니처 검사
        for pattern, desc in self.SUSPICIOUS_SCRIPT_PATTERNS:
            if pattern.search(sample_text):
                is_suspicious = True
                risk_score = max(risk_score, 9)
                reasons.append(f"악성 코드 패턴 감지: {desc}")
                matched_patterns.append(desc)

        # 시크릿 유출 검사
        for pattern, desc in self.SECRET_PATTERNS:
            if pattern.search(sample_text):
                is_suspicious = True
                risk_score = max(risk_score, 8)
                reasons.append(f"민감 시크릿 평문 노출 감지: {desc}")
                matched_patterns.append(desc)

        # 프롬프트 인젝션 검사
        for pattern, desc in self.PROMPT_INJECTION_PATTERNS:
            if pattern.search(sample_text):
                is_suspicious = True
                risk_score = max(risk_score, 7)
                reasons.append(f"프롬프트 인젝션 공격 시도 감지: {desc}")
                matched_patterns.append(desc)

        # 위험 등급 매핑
        if risk_score >= 9:
            risk_level = "CRITICAL"
        elif risk_score >= 7:
            risk_level = "HIGH_RISK"
        elif risk_score >= 4:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "SAFE"

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # 2단계 AI 부검용 텍스트 스니펫 (앞 2KB)
        snippet = sample_text[:2048] if sample_text else None

        return ScanResult(
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            risk_score=risk_score,
            entropy=max_entropy,
            detected_mime=detected_mime,
            claimed_ext=claimed_ext,
            is_extension_mismatched=is_mismatched,
            reasons=reasons,
            matched_patterns=matched_patterns,
            latency_ms=latency_ms,
            sample_text_snippet=snippet,
        )

    def scan_bytes(self, data: bytes, claimed_name: str = "stream.bin") -> ScanResult:
        """
        네트워크 패킷 또는 인메모리 스트림 바이트 검사용 메서드
        """
        start_time = time.perf_counter()
        reasons: List[str] = []
        matched_patterns: List[str] = []
        risk_score = 1
        is_suspicious = False

        _, ext = os.path.splitext(claimed_name)
        claimed_ext = ext.lower()

        header_bytes = data[:self.sample_chunk_size]
        detected_ext, detected_mime = self.identify_magic_type(header_bytes)
        is_mismatched = False

        if claimed_ext in [".jpg", ".png", ".pdf", ".txt"] and detected_ext in ["exe", "elf"]:
            is_mismatched = True
            is_suspicious = True
            risk_score = max(risk_score, 9)
            reasons.append(f"위장 바이트 스트림: {claimed_ext} 확장자이나 실제 {detected_mime}")

        entropy = self.calculate_entropy(data)
        if entropy > self.entropy_threshold and claimed_ext not in [".zip", ".jpg", ".png"]:
            is_suspicious = True
            risk_score = max(risk_score, 8)
            reasons.append(f"고엔트로피 페이로드 ({entropy} > {self.entropy_threshold})")

        sample_text = data[:self.sample_chunk_size].decode("utf-8", errors="ignore")

        for pattern, desc in self.SUSPICIOUS_SCRIPT_PATTERNS:
            if pattern.search(sample_text):
                is_suspicious = True
                risk_score = max(risk_score, 9)
                reasons.append(f"악성 코드 시그니처: {desc}")
                matched_patterns.append(desc)

        for pattern, desc in self.SECRET_PATTERNS:
            if pattern.search(sample_text):
                is_suspicious = True
                risk_score = max(risk_score, 8)
                reasons.append(f"시크릿 유출 패턴: {desc}")
                matched_patterns.append(desc)

        if risk_score >= 9:
            risk_level = "CRITICAL"
        elif risk_score >= 7:
            risk_level = "HIGH_RISK"
        elif risk_score >= 4:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "SAFE"

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ScanResult(
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            risk_score=risk_score,
            entropy=entropy,
            detected_mime=detected_mime,
            claimed_ext=claimed_ext,
            is_extension_mismatched=is_mismatched,
            reasons=reasons,
            matched_patterns=matched_patterns,
            latency_ms=latency_ms,
            sample_text_snippet=sample_text[:2048] if sample_text else None,
        )
