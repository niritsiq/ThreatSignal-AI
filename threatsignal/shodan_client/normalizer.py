"""Normalizes raw Shodan data into structured AttackSurface object."""

from __future__ import annotations

import logging

from threatsignal.models.schemas import AttackSurface, ServiceInfo

logger = logging.getLogger(__name__)

CRITICAL_PORTS = {22, 23, 3389, 1433, 5432, 27017, 6379, 9200, 2375, 4444}


class AttackSurfaceNormalizer:
    def parse(self, raw: dict, domain: str = "") -> AttackSurface:
        ips: list[str] = []
        ports: set[int] = set()
        services: list[ServiceInfo] = []
        cves: set[str] = set()
        hostnames: set[str] = set()
        org = "unknown"
        country = "unknown"

        all_data: list[dict] = []

        for host in raw.get("hosts", []):
            ip = host.get("ip_str", "")
            if ip and ip not in ips:
                ips.append(ip)
            org = host.get("org", org)
            country = host.get("country_name", country)
            hostnames.update(host.get("hostnames", []))
            all_data.extend(host.get("data", []))

        for match in raw.get("search_results", []):
            ip = match.get("ip_str", "")
            if ip and ip not in ips:
                ips.append(ip)
            all_data.append(match)

        for banner in all_data:
            port = banner.get("port", 0)
            if port:
                ports.add(port)
            product = banner.get("product", "unknown") or "unknown"
            version = banner.get("version", "unknown") or "unknown"
            cpe_list = banner.get("cpe", []) or []
            cpe = cpe_list[0] if cpe_list else ""
            svc = ServiceInfo(port=port, product=product, version=version, cpe=cpe)
            if svc not in services:
                services.append(svc)
            for cve_id in banner.get("vulns") or {}:
                cves.add(cve_id)

        score = self._compute_score(list(ports), list(cves), services)
        surface = AttackSurface(
            ips=ips,
            open_ports=sorted(ports),
            services=services[:20],  # cap at 20
            cve_indicators=list(cves)[:10],
            hostnames=list(hostnames)[:10],
            org=org,
            country=country,
            attack_surface_score=round(score, 2),
        )
        surface.snapshot_text = self._build_snapshot(surface, domain)
        logger.info(
            "Attack surface parsed for %s: %d IPs, %d ports, %d CVEs, score=%.2f",
            domain,
            len(ips),
            len(ports),
            len(cves),
            score,
        )
        return surface

    def _compute_score(self, ports: list[int], cves: list[str], services: list[ServiceInfo]) -> float:
        score = 0.0
        score += min(len(ports) / 5.0, 3.0)  # port breadth, max 3
        score += min(len(cves) * 1.5, 4.0)  # CVE exposure, max 4
        if any(p in CRITICAL_PORTS for p in ports):
            score += 1.0  # critical port flag
        if len(ports) > 15:
            score += 1.0  # large surface flag
        if len(services) > 10:
            score += 1.0  # many services
        return min(score, 10.0)

    def _build_snapshot(self, surface: AttackSurface, domain: str) -> str:
        service_desc = (
            ", ".join(f"{s.product} {s.version} (port {s.port})" for s in surface.services[:5])
            or "no services detected"
        )

        cve_desc = ", ".join(surface.cve_indicators[:5]) or "none detected"
        hostname_desc = ", ".join(surface.hostnames[:5]) or "none"

        return (
            f"Domain {domain or 'unknown'} resolves to {len(surface.ips)} IP(s) "
            f"hosted by {surface.org} ({surface.country}). "
            f"Open ports: {surface.open_ports[:10]}. "
            f"Detected services include: {service_desc}. "
            f"Known CVE indicators: {cve_desc}. "
            f"Observed hostnames: {hostname_desc}. "
            f"Attack surface score: {surface.attack_surface_score}/10."
        )
