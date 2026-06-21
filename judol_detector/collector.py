"""Collector - Mengumpulkan DNS query logs dari Pi-hole v6 REST API.

Pi-hole v6 menggunakan session-based authentication.
Endpoint: /api/auth (POST) untuk login, /api/queries (GET) untuk query log.
"""

import logging
import requests
from typing import Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class PiholeCollector:
    """Mengumpulkan DNS query dari Pi-hole v6 API."""

    def __init__(self, base_url: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        self.sid: Optional[str] = None
        # Timeout rendah untuk Raspberry Pi network
        self.timeout = 30

    def _api_url(self, path: str) -> str:
        """Build full API URL."""
        return f"{self.base_url}/api{path}"

    def authenticate(self) -> bool:
        """Authenticate ke Pi-hole v6 dan dapatkan session ID."""
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
                logger.info("Berhasil login ke Pi-hole")
                return True
            else:
                logger.error("Login Pi-hole gagal: session tidak valid")
                return False

        except requests.exceptions.ConnectionError:
            logger.error(f"Tidak bisa terhubung ke Pi-hole di {self.base_url}")
            return False
        except requests.exceptions.Timeout:
            logger.error("Timeout saat menghubungi Pi-hole")
            return False
        except Exception as e:
            logger.error(f"Error saat autentikasi Pi-hole: {e}")
            return False

    def fetch_queries(self, limit: int = 1000, since_timestamp: Optional[float] = None) -> list[dict]:
        """Ambil DNS query terbaru dari Pi-hole.
        
        Returns:
            List of query dicts dengan minimal key 'domain'
        """
        if not self.sid:
            if not self.authenticate():
                return []

        try:
            params = {"length": limit}
            if since_timestamp is not None:
                params["from"] = int(since_timestamp)

            resp = self.session.get(
                self._api_url("/queries"),
                params=params,
                timeout=self.timeout
            )
            
            # Re-auth jika session expired
            if resp.status_code in (401, 403):
                logger.warning("Session expired, re-authenticating...")
                if self.authenticate():
                    resp = self.session.get(
                        self._api_url("/queries"),
                        params=params,
                        timeout=self.timeout
                    )
                else:
                    return []

            resp.raise_for_status()
            data = resp.json()
            
            queries = data.get("queries", [])
            logger.info(f"Berhasil mengambil {len(queries)} DNS queries dari Pi-hole")
            return queries

        except requests.exceptions.ConnectionError:
            logger.error(f"Koneksi ke Pi-hole terputus")
            return []
        except Exception as e:
            logger.error(f"Error mengambil queries: {e}")
            return []

    def extract_unique_domains(self, queries: list[dict]) -> list[str]:
        """Ekstrak domain unik dari query results.
        
        Pi-hole v6 API query format biasanya memiliki field 'domain'.
        """
        domains = set()
        
        for q in queries:
            domain = None
            # Pi-hole v6 format
            if isinstance(q, dict):
                domain = q.get("domain", "") or q.get("name", "")
            elif isinstance(q, (list, tuple)) and len(q) > 2:
                # Fallback format: [timestamp, type, domain, client, ...]
                domain = q[2] if len(q) > 2 else None
            
            if domain and isinstance(domain, str):
                domain = domain.lower().strip().rstrip(".")
                if domain and len(domain) > 1 and "." in domain:
                    domains.add(domain)
        
        return list(domains)

    def collect(self, limit: int = 1000, since_timestamp: Optional[float] = None) -> tuple[list[str], list[dict]]:
        """Main method: kumpulkan unique domains dari Pi-hole.
        
        Returns:
            Tuple of (list of unique domain strings, raw queries list)
        """
        queries = self.fetch_queries(limit=limit, since_timestamp=since_timestamp)
        if not queries:
            logger.info("Tidak ada query baru dari Pi-hole")
            return [], []
        
        domains = self.extract_unique_domains(queries)
        logger.info(f"Ditemukan {len(domains)} domain unik dari {len(queries)} queries")
        return domains, queries

    def close(self):
        """Tutup session."""
        try:
            if self.sid:
                self.session.delete(
                    self._api_url("/auth"),
                    timeout=self.timeout
                )
        except Exception:
            pass
        self.session.close()
