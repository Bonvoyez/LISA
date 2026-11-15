"""
LISA Fraud Shield (Layer 1/2 Unified: Smishing, Clipboard Clipper, and Wi-Fi Sentinel)
- 보이스피싱 및 스미싱 문자 문맥/패턴 지능 분석
- 가상화폐 지갑 주소 및 은행 계좌번호 클립보드 하이재킹(Clipper) 감지
- 공용 와이파이 위험도(오픈 AP, 악성 DNS 변조) 실시간 진단
- 100% 플랫폼 독립적 (Windows, Mac, Android, iOS 공통 사용)
"""

import re
from typing import List, Dict, Optional, Tuple
from pydantic import BaseModel, Field


class MessageScanResult(BaseModel):
    """문자/메시지 피싱 스캔 결과"""
    is_phishing: bool = Field(description="피싱/스미싱 여부")
    threat_type: str = Field(description="위협 유형 (가족사칭, 기관사칭, 저금리대출사기, 택배사칭 등)")
    risk_score: int = Field(description="위험 점수 (1~10)")
    reasons: List[str] = Field(default_factory=list, description="위험 판정 근거")
    detected_urls: List[str] = Field(default_factory=list, description="포함된 URL 목록")
    recommended_action: str = Field(description="권고 조치")


class ClipboardScanResult(BaseModel):
    """클립보드 계좌/지갑 하이재킹 스캔 결과"""
    is_hijacked: bool = Field(description="클리퍼 악성코드에 의한 변조 여부")
    wallet_type: Optional[str] = Field(default=None, description="가상화폐 또는 계좌 유형 (BTC, ETH, KR_BANK 등)")
    original_text: str = Field(description="사용자가 원래 복사한 원본 주소")
    tampered_text: str = Field(description="변조된 의심 주소")
    risk_score: int = Field(description="위험 점수 (1~10)")
    explanation: str = Field(description="사건 해설")


class WifiScanResult(BaseModel):
    """와이파이 보안 진단 결과"""
    is_dangerous: bool = Field(description="위험한 와이파이 여부")
    ssid: str = Field(description="와이파이 이름")
    risk_score: int = Field(description="위험 점수 (1~10)")
    warnings: List[str] = Field(default_factory=list, description="경고 항목 목록")
    recommended_action: str = Field(description="권고 수칙")


class FraudShield:
    """통합 사기 및 환경 위협 방어 엔진"""

    # 1. 스미싱/피싱 카테고리별 패턴
    PHISHING_PATTERNS = [
        # (1) 가족 사칭 (자녀 사칭 액정 파손형)
        (
            re.compile(r"(엄마|아빠|어머니|아버지).*?(폰|액정|핸드폰).*?(깨|고장|수리|임시|친구폰).*?(상품권|인증번호|결제|원격)", re.IGNORECASE | re.DOTALL),
            "가족_사칭_상품권_피싱",
            9,
            "자녀나 가족을 사칭하여 휴대폰 파손을 핑계로 상품권 구매나 결제를 유도하는 전형적인 메신저 피싱입니다."
        ),
        # (2) 국가기관 사칭 (검찰/경찰/금감원)
        (
            re.compile(r"(서울중앙지검|대검찰청|금융감독원|경찰청).*?(출석요구서|불법자금|계좌동결|사건번호|자산보호)", re.IGNORECASE),
            "국가기관_사칭_피싱",
            10,
            "검찰 또는 금융감독원을 사칭하여 계좌 동결이나 출석을 빌미로 금전을 요구하는 전형적인 보이스피싱 수법입니다."
        ),
        # (3) 정부지원 저금리 대출/생계지원금 사칭
        (
            re.compile(r"(정부지원|신용보증재단|소상공인|긴급생계).*?(저금리|대환|무이자|선착순|한도조회).*?(http|신청)", re.IGNORECASE),
            "정부지원_대출_사기",
            8,
            "정부 기관을 사칭하여 저금리 대환 대출이나 지원금을 미끼로 악성 앱 설치를 유도하는 금융 사기 문자입니다."
        ),
        # (4) 택배 배송조회/주소 불일치 사칭
        (
            re.compile(r"(CJ대한통운|한진택배|우체국).*?(주소지|도로명|미수령|보관).*?(http|확인|조회)", re.IGNORECASE),
            "택배_사칭_스미싱",
            8,
            "택배 미수령이나 배송지 오류를 사칭하여 가짜 배송조회 앱(.apk) 설치를 유도하는 스미싱 문자입니다."
        ),
        # (5) 모바일 청첩장/부고장 사칭
        (
            re.compile(r"(모바일\s*청첩장|결혼식|부고장|장례식장).*?(http[s]?://[^\s]+)", re.IGNORECASE),
            "경조사_사칭_스미싱",
            8,
            "모바일 청첩장이나 부고장 링크를 위장하여 스마트폰에 악성코드를 심으려는 스미싱 문자입니다."
        ),
    ]

    # 가상화폐 및 계좌 정규식
    CRYPTO_PATTERNS = {
        "Bitcoin (Legacy)": re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
        "Bitcoin (SegWit/Bech32)": re.compile(r"^bc1[a-z0-9]{39,59}$"),
        "Ethereum": re.compile(r"^0x[a-fA-F0-9]{40}$"),
        "Korea Bank Account": re.compile(r"^\d{3,6}-\d{2,6}-\d{3,8}$"),
    }

    # 알려진 신뢰 공인 DNS 서버 목록
    TRUSTED_DNS_SERVERS = {
        "8.8.8.8", "8.8.4.4",          # Google
        "1.1.1.1", "1.0.0.1",          # Cloudflare
        "9.9.9.9", "149.112.112.112",  # Quad9
        "208.67.222.222", "208.67.220.220", # OpenDNS
        "168.126.63.1", "168.126.63.2",     # KT DNS
        "219.250.36.130", "210.220.163.82", # SKT DNS
        "164.124.101.2", "203.248.252.2",   # LGU+ DNS
    }

    URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)

    def analyze_message(self, message_text: str, lang: str = "ko") -> MessageScanResult:
        """
        문자/메신저 텍스트 피싱/스미싱 실시간 검사
        """
        urls = self.URL_REGEX.findall(message_text)
        is_phishing = False
        threat_type = "정상" if lang == "ko" else "CLEAN"
        risk_score = 1
        reasons: List[str] = []

        # 단축 URL (bit.ly, tinyurl 등) 포함 시 의심 가산점
        for u in urls:
            if any(shortener in u.lower() for shortener in ["bit.ly", "tinyurl.com", "is.gd", "t.co", "me2.do"]):
                risk_score = max(risk_score, 6)
                reasons.append("단축 URL(bit.ly 등)이 포함되어 실제 도착지 은폐 의심.")

        # 문맥 패턴 검사
        for pattern, cat, score, expl in self.PHISHING_PATTERNS:
            if pattern.search(message_text):
                is_phishing = True
                threat_type = cat if lang == "ko" else cat.upper()
                risk_score = max(risk_score, score)
                reasons.append(expl if lang == "ko" else f"Detected malicious pretext: {cat}")
                break

        if is_phishing or risk_score >= 7:
            rec_action = "링크 클릭 절대 금지 및 즉시 삭제" if lang == "ko" else "DO NOT CLICK LINKS & DELETE IMMEDIATELY"
        else:
            rec_action = "정상 메시지로 판단됨" if lang == "ko" else "Normal message"

        return MessageScanResult(
            is_phishing=is_phishing,
            threat_type=threat_type,
            risk_score=risk_score,
            reasons=reasons,
            detected_urls=urls,
            recommended_action=rec_action
        )

    def analyze_clipboard(self, original_copied: str, current_clipboard: str) -> ClipboardScanResult:
        """
        클립보드 하이재킹(Clipper 악성코드) 변조 감지
        사용자가 복사한 원본 주소 vs 현재 클립보드 주소 비교
        """
        orig_clean = original_copied.strip()
        curr_clean = current_clipboard.strip()

        # 원본과 현재가 동일하면 안전
        if orig_clean == curr_clean:
            return ClipboardScanResult(
                is_hijacked=False,
                wallet_type=None,
                original_text=orig_clean,
                tampered_text=curr_clean,
                risk_score=1,
                explanation="클립보드 내용이 변조되지 않았습니다 (정상)."
            )

        # 원본이 금융/가상화폐 주소 패턴인지 확인
        detected_type = None
        for w_type, regex in self.CRYPTO_PATTERNS.items():
            if regex.match(orig_clean):
                detected_type = w_type
                break

        # 원본이 가상화폐나 계좌인데 다른 주소로 교체되었다면 클리퍼 공격 100%
        if detected_type and orig_clean != curr_clean:
            return ClipboardScanResult(
                is_hijacked=True,
                wallet_type=detected_type,
                original_text=orig_clean,
                tampered_text=curr_clean,
                risk_score=10,
                explanation=f"🚨 치명적 위험: [{detected_type}] 주소를 복사하는 순간, 백그라운드 악성코드가 해커의 다른 주소로 가로채 바꿔치기했습니다! 절대 송금하지 마세요."
            )

        return ClipboardScanResult(
            is_hijacked=False,
            wallet_type=None,
            original_text=orig_clean,
            tampered_text=curr_clean,
            risk_score=2,
            explanation="일반 텍스트 클립보드 변경 (정상 사용자 복사)."
        )

    def analyze_wifi(
        self,
        ssid: str,
        is_open_network: bool,
        dns_servers: List[str],
        gateway_ip: Optional[str] = None
    ) -> WifiScanResult:
        """
        공용 와이파이 보안 취약성 및 DNS 오염 진단
        """
        warnings: List[str] = []
        risk_score = 1
        is_dangerous = False

        # 1. 오픈 와이파이(비밀번호 없음) 검사
        if is_open_network:
            is_dangerous = True
            risk_score = max(risk_score, 7)
            warnings.append(f"비밀번호가 없는 미암호화(Open) 공용 와이파이 '{ssid}'에 연결되었습니다. 동일 망 내 패킷 도청(Sniffing) 위험이 있습니다.")

        # 2. DNS 서버 안전성 검사
        for dns in dns_servers:
            # 로컬 공유기 IP(192.168.x.x, 10.x.x.x)이거나 검증된 공인 DNS가 아닌 생소한 외부 IP인 경우
            if not dns.startswith(("192.168.", "10.", "172.16.", "127.")):
                if dns not in self.TRUSTED_DNS_SERVERS:
                    is_dangerous = True
                    risk_score = max(risk_score, 8)
                    warnings.append(f"의심스러운 DNS 서버 주소({dns}) 감지: 파밍(가짜 금융사이트 유도) 공격에 주의하세요.")

        if is_dangerous:
            rec = "중요 금융 거래 및 포털 로그인 자제 권고 (VPN 사용 권장)"
        else:
            rec = "안전하게 암호화된 정상 네트워크입니다."

        return WifiScanResult(
            is_dangerous=is_dangerous,
            ssid=ssid,
            risk_score=risk_score,
            warnings=warnings,
            recommended_action=rec
        )
