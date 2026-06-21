"""Analyzer - Analisis domain menggunakan DeepSeek LLM.

Menggunakan DeepSeek API (OpenAI-compatible) untuk mendeteksi
domain judi online (judol) dari list domain DNS query.
Dilengkapi fallback rule-based jika API gagal.
"""

import json
import logging
import re
import time
from typing import Optional
from openai import OpenAI

logger = logging.getLogger(__name__)

# Keyword dan pola yang sering digunakan domain judol Indonesia
JUDOL_KEYWORDS = {
    # Keyword langsung
    "slot", "togel", "toge", "poker", "casino", "kasino", "baccarat",
    "blackjack", "roulette", "sbobet", "maxbet", "ibcbet",
    "betting", "taruhan", "judi", "judol",
    # Keyword gacor/slang
    "gacor", "maxwin", "scatter", "jackpot", "jp", "cuan",
    "rtp", "pragmatic", "pgsoft", "habanero", "spadegaming",
    "microgaming", "joker123", "joker388",
    # Platform patterns
    "toto", "4d", "togel4d", "togelsgp", "togelhk",
    "bandar", "agen", "daftar", "login", "link",
    "bo", "situs",
    # Provider patterns
    "pragmaticplay", "pgslot", "slotgacor", "slot88",
    "depo", "deposit", "withdraw", "wd",
    "bonus", "promo", "freebet", "freechip",
    # Specific known patterns
    "hoki", "hokibet", "lucky", "win", "bet",
    "88", "77", "99", "168", "138", "369",
    "zeus", "olympus", "gates", "starlight", "bonanza",
    "mahjong", "ways",
}

# TLD yang sering digunakan judol
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".bid", ".click", ".club",
    ".icu", ".buzz", ".fun", ".lol", ".sbs",
    ".cfd", ".cyou", ".rest", ".bond", ".skin",
}

SYSTEM_PROMPT = """Kamu adalah sistem keamanan jaringan yang menganalisis domain DNS untuk mendeteksi website judi online (judol) Indonesia.

Tugas: Dari daftar domain yang diberikan, identifikasi domain yang kemungkinan besar adalah situs judi online.

Kriteria domain judol:
1. Mengandung kata kunci: slot, togel, poker, casino, judi, gacor, maxwin, scatter, betting, taruhan, sbobet, toto, bandar, rtp
2. Pola nama mencurigakan: kombinasi kata + angka random (contoh: slot88gacor.com, togelmania123.xyz)
3. TLD mencurigakan yang sering digunakan judol: .xyz, .top, .bid, .click, .club, .icu, .buzz, .fun
4. Provider game judol: pragmatic, pgsoft, habanero, joker123, spadegaming
5. Pola deposit/withdraw: depo, wd, bonus, freebet, freechip
6. Nama-nama game slot populer: zeus, olympus, gates of olympus, starlight princess, bonanza, mahjong ways

IMPORTANT RULES:
- HANYA flagging domain yang benar-benar mencurigakan judol
- Domain berita, e-commerce, sosial media, teknologi = BUKAN judol
- Jangan flag domain yang legitimate meskipun mengandung angka
- Berikan confidence score 0.0 - 1.0
- Confidence >= 0.7 = sangat yakin judol
- Confidence 0.4 - 0.7 = mencurigakan
- Confidence < 0.4 = mungkin bukan judol

FORMAT OUTPUT (STRICT JSON ONLY, no markdown, no explanation):
{"flagged": [{"domain": "example.com", "confidence": 0.95, "reason": "alasan singkat"}]}

Jika tidak ada domain judol, output: {"flagged": []}"""


class DeepSeekAnalyzer:
    """Analisis domain menggunakan DeepSeek API."""

    def __init__(self, api_key: str, base_url: str = "https://api.deepseek.com",
                 model: str = "deepseek-chat"):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )
        self.model = model
        self.max_retries = 3
        self.retry_delay = 5  # seconds

    def analyze_batch(self, domains: list[str]) -> list[dict]:
        """Analisis batch domain menggunakan DeepSeek.
        
        Args:
            domains: List of domain strings to analyze
            
        Returns:
            List of dicts: {domain, is_judol, confidence, reason}
        """
        if not domains:
            return []

        # Siapkan prompt
        domain_list = "\n".join(f"- {d}" for d in domains)
        user_prompt = f"Analisis domain berikut dan identifikasi yang merupakan situs judi online:\n\n{domain_list}"

        # Call DeepSeek API dengan retry
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.1,  # Low temperature untuk konsistensi
                    max_tokens=4096,
                    response_format={"type": "json_object"},
                )

                result_text = response.choices[0].message.content.strip()
                return self._parse_response(result_text, domains)

            except Exception as e:
                logger.warning(
                    f"DeepSeek API error (attempt {attempt}/{self.max_retries}): {e}"
                )
                if attempt < self.max_retries:
                    wait = self.retry_delay * attempt
                    logger.info(f"Retry dalam {wait} detik...")
                    time.sleep(wait)
                else:
                    logger.error("DeepSeek API gagal setelah semua retry, menggunakan fallback rule-based")
                    return self._rule_based_fallback(domains)

        return []

    def _parse_response(self, response_text: str, all_domains: list[str]) -> list[dict]:
        """Parse response JSON dari DeepSeek."""
        results = []
        flagged_domains = set()

        try:
            # Coba parse JSON langsung
            data = json.loads(response_text)
            flagged = data.get("flagged", [])

            for item in flagged:
                domain = item.get("domain", "").lower().strip()
                confidence = float(item.get("confidence", 0.0))
                reason = item.get("reason", "Terdeteksi oleh LLM")

                if domain and confidence >= 0.4:
                    flagged_domains.add(domain)
                    results.append({
                        "domain": domain,
                        "is_judol": True,
                        "confidence": confidence,
                        "reason": reason
                    })

        except json.JSONDecodeError:
            logger.warning("Gagal parse JSON dari DeepSeek, mencoba ekstrak manual")
            # Fallback: coba ekstrak JSON dari text
            json_match = re.search(r'\{[^{}]*"flagged"[^{}]*\[.*?\][^{}]*\}', 
                                   response_text, re.DOTALL)
            if json_match:
                try:
                    data = json.loads(json_match.group())
                    return self._parse_response(json.dumps(data), all_domains)
                except json.JSONDecodeError:
                    pass
            
            logger.error("Tidak bisa parse response DeepSeek, fallback ke rule-based")
            return self._rule_based_fallback(all_domains)

        # Tandai domain yang tidak di-flag sebagai safe
        for domain in all_domains:
            if domain.lower() not in flagged_domains:
                results.append({
                    "domain": domain.lower(),
                    "is_judol": False,
                    "confidence": 0.0,
                    "reason": "Tidak terdeteksi sebagai judol"
                })

        return results

    def _rule_based_fallback(self, domains: list[str]) -> list[dict]:
        """Fallback detection menggunakan rule-based pattern matching.
        
        Digunakan ketika DeepSeek API gagal.
        """
        results = []
        
        for domain in domains:
            domain_lower = domain.lower()
            score = 0.0
            reasons = []

            # Check keywords
            keyword_hits = []
            for kw in JUDOL_KEYWORDS:
                if kw in domain_lower:
                    keyword_hits.append(kw)
            
            if len(keyword_hits) >= 3:
                score += 0.6
                reasons.append(f"Multiple keyword match: {', '.join(keyword_hits[:5])}")
            elif len(keyword_hits) >= 2:
                score += 0.4
                reasons.append(f"Keyword match: {', '.join(keyword_hits)}")
            elif len(keyword_hits) == 1:
                score += 0.2
                reasons.append(f"Keyword: {keyword_hits[0]}")

            # Check suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if domain_lower.endswith(tld):
                    score += 0.15
                    reasons.append(f"Suspicious TLD: {tld}")
                    break

            # Check angka berlebihan
            digit_count = sum(1 for c in domain_lower.split(".")[0] if c.isdigit())
            if digit_count >= 3:
                score += 0.1
                reasons.append("Banyak angka di domain")

            # Check panjang domain name yang pendek + angka (pola judol)
            name_part = domain_lower.split(".")[0]
            if re.match(r'^[a-z]+\d{2,4}$', name_part) and any(kw in name_part for kw in JUDOL_KEYWORDS):
                score += 0.2
                reasons.append("Pola nama+angka khas judol")

            is_judol = score >= 0.4
            confidence = min(score, 1.0)

            results.append({
                "domain": domain_lower,
                "is_judol": is_judol,
                "confidence": confidence,
                "reason": "; ".join(reasons) if reasons else "Tidak ada indikasi judol (rule-based)"
            })

        return results


def analyze_domains(api_key: str, base_url: str, model: str,
                    domains: list[str], batch_size: int = 100) -> list[dict]:
    """Convenience function untuk analisis domain.
    
    Membagi domain ke batch dan menganalisis masing-masing.
    """
    analyzer = DeepSeekAnalyzer(api_key=api_key, base_url=base_url, model=model)
    all_results = []

    # Bagi ke batch
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i + batch_size]
        logger.info(f"Menganalisis batch {i // batch_size + 1} ({len(batch)} domain)...")
        results = analyzer.analyze_batch(batch)
        all_results.extend(results)
        
        # Delay antar batch untuk menghindari rate limit
        if i + batch_size < len(domains):
            time.sleep(2)

    return all_results
