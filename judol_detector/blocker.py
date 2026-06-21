"""Blocker - Memblokir domain judol di Pi-hole v6.

Menggunakan Pi-hole v6 REST API untuk menambahkan domain
ke deny list (blacklist). Juga mendukung unblock.
"""

import logging
import requests
from typing import Optional

logger = logging.getLogger(__name__)


class PiholeBlocker:
    """Interface untuk block/unblock domain di Pi-hole v6."""

    def __init__(self, base_url: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        self.sid: Optional[str] = None
        self.timeout = 30

    def _api_url(self, path: str) -> str:
        return f"{self.base_url}/api{path}"

    def authenticate(self) -> bool:
        """Login ke Pi-hole v6."""
        try:
            resp = self.session.post(
                self._api_url("/auth"),
                json={"password": self.password},
                timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("session", {}).get("valid"):
                self.sid = data["session"].get("sid", "")
                # Set SID sebagai custom HTTP header untuk request berikutnya (menghindari CSRF check)
                self.session.headers.update({"sid": self.sid})
                logger.debug("Blocker: authenticated to Pi-hole")
                return True
            return False

        except Exception as e:
            logger.error(f"Blocker auth error: {e}")
            return False

    def _ensure_auth(self) -> bool:
        """Pastikan sudah login."""
        if not self.sid:
            return self.authenticate()
        return True

    def block_domain(self, domain: str, comment: str = "Blocked by Judol Detector") -> bool:
        """Tambahkan domain ke Pi-hole deny list.
        
        Args:
            domain: Domain yang akan diblokir
            comment: Komentar/alasan blocking
            
        Returns:
            True jika berhasil
        """
        if not self._ensure_auth():
            logger.error(f"Gagal memblokir {domain}: Autentikasi ke Pi-hole gagal")
            return False

        try:
            payload = {
                "domain": domain,
                "comment": comment,
            }
            
            resp = self.session.post(
                self._api_url("/domains/deny/exact"),
                json=payload,
                timeout=self.timeout
            )

            # Re-auth if needed
            if resp.status_code in (401, 403):
                logger.warning("Session expired saat memblokir domain, mencoba re-auth...")
                if self.authenticate():
                    resp = self.session.post(
                        self._api_url("/domains/deny/exact"),
                        json=payload,
                        timeout=self.timeout
                    )

            logger.info(f"Response pemblokiran {domain}: HTTP {resp.status_code}")

            if resp.status_code in (200, 201):
                logger.info(f"✓ Berhasil memblokir domain: {domain}")
                return True
            elif resp.status_code == 409:
                logger.info(f"✓ Domain sudah ada di deny list (sudah terblokir): {domain}")
                return True
            else:
                logger.error(
                    f"✗ Gagal memblokir {domain}: HTTP {resp.status_code} - {resp.text}"
                )
                return False

        except Exception as e:
            logger.error(f"✗ Error saat memblokir {domain}: {e}")
            return False

    def unblock_domain(self, domain: str) -> bool:
        """Hapus domain dari Pi-hole deny list."""
        if not self._ensure_auth():
            logger.error(f"Gagal melakukan unblock {domain}: Autentikasi ke Pi-hole gagal")
            return False

        try:
            resp = self.session.delete(
                self._api_url(f"/domains/deny/exact/{domain}"),
                timeout=self.timeout
            )

            if resp.status_code in (401, 403):
                logger.warning("Session expired saat unblock domain, mencoba re-auth...")
                if self.authenticate():
                    resp = self.session.delete(
                        self._api_url(f"/domains/deny/exact/{domain}"),
                        timeout=self.timeout
                    )

            logger.info(f"Response unblock {domain}: HTTP {resp.status_code}")

            if resp.status_code in (200, 204):
                logger.info(f"✓ Berhasil unblock domain: {domain}")
                return True
            elif resp.status_code == 404:
                logger.info(f"✓ Domain tidak ada di deny list (memang tidak terblokir): {domain}")
                return True
            else:
                logger.error(
                    f"✗ Gagal unblock {domain}: HTTP {resp.status_code} - {resp.text}"
                )
                return False

        except Exception as e:
            logger.error(f"✗ Error saat unblock {domain}: {e}")
            return False

    def block_domains(self, domains: list[str],
                      comment: str = "Blocked by Judol Detector") -> dict:
        """Block multiple domains.
        
        Returns:
            Dict with 'success' and 'failed' counts
        """
        result = {"success": 0, "failed": 0, "domains": []}
        
        for domain in domains:
            if self.block_domain(domain, comment):
                result["success"] += 1
                result["domains"].append(domain)
            else:
                result["failed"] += 1
        
        return result

    def close(self):
        """Tutup session."""
        try:
            if self.sid:
                self.session.delete(self._api_url("/auth"), timeout=self.timeout)
        except Exception:
            pass
        self.session.close()
