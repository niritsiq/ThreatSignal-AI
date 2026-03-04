"""Shodan API client — queries domain exposure data."""
from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)


class ShodanClient:
    def __init__(self, api_key: str):
        import shodan
        self.api = shodan.Shodan(api_key)

    def query_domain(self, domain: str) -> dict:
        """
        Query Shodan for all data related to a domain.

        Strategy:
          1. Resolve IPs via socket (no Shodan credits needed, works on free tier)
          2. For each IP call api.host() — available on free tier
          3. Attempt api.search() as bonus (requires paid plan; silently skipped if 403)

        Returns combined raw dict with keys: hosts, search_results.
        """
        result: dict = {"hosts": [], "search_results": []}
        ips_seen: set = set()

        # Strategy 1: resolve domain → IPs via socket (free, always works)
        try:
            _, _, ip_list = socket.gethostbyname_ex(domain)
            for ip in ip_list:
                if ip not in ips_seen:
                    ips_seen.add(ip)
                    try:
                        host = self.api.host(ip)
                        result["hosts"].append(host)
                        logger.info(f"Shodan host data fetched for {ip}")
                    except Exception as e:
                        logger.warning(f"Shodan host lookup failed for {ip}: {e}")
        except socket.gaierror as e:
            logger.warning(f"DNS resolution failed for {domain}: {e}")

        # Strategy 2: search (requires paid Shodan plan; skipped gracefully on free tier)
        try:
            search = self.api.search(f"hostname:{domain}", limit=10)
            result["search_results"] = search.get("matches", [])
            logger.info(f"Shodan search returned {len(result['search_results'])} results")
        except Exception as e:
            logger.warning(f"Shodan search skipped (free tier or error): {e}")

        return result
