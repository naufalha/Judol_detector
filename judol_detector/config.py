"""Configuration loader - semua konfigurasi dari .env file."""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load .env dari root project
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _PROJECT_ROOT / ".env"

if _ENV_PATH.exists():
    load_dotenv(_ENV_PATH)
else:
    # Hanya cetak peringatan jika environment variable penting belum diset (misal di Docker)
    if not os.getenv("PIHOLE_PASSWORD") or not os.getenv("DEEPSEEK_API_KEY"):
        print(f"[WARNING] File .env tidak ditemukan di {_ENV_PATH}")
        print(f"          Salin .env.example ke .env dan isi konfigurasinya.")


class Config:
    """Konfigurasi aplikasi dari environment variables."""

    # Pi-hole v6
    PIHOLE_URL: str = os.getenv("PIHOLE_URL", "http://192.168.1.1")
    PIHOLE_PASSWORD: str = os.getenv("PIHOLE_PASSWORD", "")

    # DeepSeek API
    DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_BASE_URL: str = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    DEEPSEEK_MODEL: str = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    # Scan
    SCAN_INTERVAL: int = int(os.getenv("SCAN_INTERVAL", "60").strip())
    BATCH_SIZE: int = int(os.getenv("BATCH_SIZE", "100").strip())
    QUERY_LIMIT: int = int(os.getenv("QUERY_LIMIT", "1000").strip())

    # Behavior
    AUTO_BLOCK: bool = os.getenv("AUTO_BLOCK", "false").strip().lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").strip()
    DB_PATH: str = os.getenv("DB_PATH", str(_PROJECT_ROOT / "data" / "judol_history.db"))
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", str(_PROJECT_ROOT / "reports"))

    # Whitelist - domain populer yang tidak perlu dianalisis
    WHITELIST_DOMAINS: set = {
        "google.com", "google.co.id", "googleapis.com", "gstatic.com",
        "youtube.com", "ytimg.com", "googlevideo.com", "ggpht.com",
        "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
        "twitter.com", "x.com", "twimg.com",
        "whatsapp.com", "whatsapp.net",
        "tiktok.com", "tiktokcdn.com", "tiktokv.com",
        "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
        "apple.com", "icloud.com", "mzstatic.com",
        "amazon.com", "amazonaws.com", "cloudfront.net",
        "cloudflare.com", "cloudflare-dns.com",
        "github.com", "githubusercontent.com", "githubassets.com",
        "stackoverflow.com", "stackexchange.com",
        "wikipedia.org", "wikimedia.org",
        "netflix.com", "nflxvideo.net", "nflximg.net",
        "spotify.com", "scdn.co", "spotifycdn.com",
        "reddit.com", "redditmedia.com", "redditstatic.com",
        "telegram.org", "t.me",
        "linkedin.com", "licdn.com",
        "zoom.us", "zoomgov.com",
        "shopee.co.id", "tokopedia.com", "bukalapak.com", "lazada.co.id",
        "gojek.com", "grab.com", "dana.id", "ovo.id",
        "detik.com", "kompas.com", "tribunnews.com", "liputan6.com",
        "pi.hole", "localhost",
        # Infrastructure
        "in-addr.arpa", "ip6.arpa", "local", "lan",
        "pool.ntp.org", "debian.org", "raspbian.org", "raspberrypi.org",
        "docker.com", "docker.io",
    }

    @classmethod
    def validate(cls) -> list[str]:
        """Validasi konfigurasi, return list error messages."""
        errors = []
        if not cls.PIHOLE_PASSWORD:
            errors.append("PIHOLE_PASSWORD belum diset di .env")
        if not cls.DEEPSEEK_API_KEY:
            errors.append("DEEPSEEK_API_KEY belum diset di .env")
        if cls.SCAN_INTERVAL < 10:
            errors.append("SCAN_INTERVAL minimum 10 detik")
        if cls.BATCH_SIZE < 1 or cls.BATCH_SIZE > 500:
            errors.append("BATCH_SIZE harus antara 1-500")
        return errors

    @classmethod
    def is_whitelisted(cls, domain: str) -> bool:
        """Cek apakah domain ada di whitelist (termasuk subdomain)."""
        domain = domain.lower().strip().rstrip(".")
        for wl in cls.WHITELIST_DOMAINS:
            if domain == wl or domain.endswith("." + wl):
                return True
        return False
