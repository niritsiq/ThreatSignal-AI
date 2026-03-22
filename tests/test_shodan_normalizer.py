"""Tests for Shodan attack surface normalizer."""

import pytest

from threatsignal.shodan_client.normalizer import AttackSurfaceNormalizer


@pytest.fixture
def normalizer():
    return AttackSurfaceNormalizer()


def test_parse_basic_host(normalizer):
    raw = {
        "hosts": [
            {
                "ip_str": "1.2.3.4",
                "org": "Test Corp",
                "country_name": "US",
                "hostnames": ["test.com"],
                "data": [{"port": 443, "product": "nginx", "version": "1.24", "cpe": [], "vulns": {}}],
            }
        ],
        "search_results": [],
    }
    result = normalizer.parse(raw, "test.com")
    assert "1.2.3.4" in result.ips
    assert 443 in result.open_ports
    assert result.services[0].product == "nginx"
    assert result.org == "Test Corp"


def test_score_increases_with_cves(normalizer):
    raw_no_cve = {
        "hosts": [
            {
                "ip_str": "1.2.3.4",
                "org": "",
                "country_name": "",
                "hostnames": [],
                "data": [{"port": 443, "product": "", "version": "", "cpe": [], "vulns": {}}],
            }
        ],
        "search_results": [],
    }
    raw_with_cve = {
        "hosts": [
            {
                "ip_str": "1.2.3.4",
                "org": "",
                "country_name": "",
                "hostnames": [],
                "data": [
                    {"port": 443, "product": "", "version": "", "cpe": [], "vulns": {"CVE-2022-0778": {"cvss": 7.5}}}
                ],
            }
        ],
        "search_results": [],
    }
    s1 = normalizer.parse(raw_no_cve, "")
    s2 = normalizer.parse(raw_with_cve, "")
    assert s2.attack_surface_score > s1.attack_surface_score


def test_score_bounded(normalizer):
    many_ports = [
        {"port": p, "product": "", "version": "", "cpe": [], "vulns": {f"CVE-{i}": {} for i in range(10)}}
        for p in range(1, 30)
    ]
    raw = {
        "hosts": [{"ip_str": "1.2.3.4", "org": "", "country_name": "", "hostnames": [], "data": many_ports}],
        "search_results": [],
    }
    result = normalizer.parse(raw, "")
    assert result.attack_surface_score <= 10.0


def test_snapshot_text_not_empty(normalizer):
    raw = {"hosts": [], "search_results": []}
    result = normalizer.parse(raw, "empty.com")
    assert len(result.snapshot_text) > 0


def test_handles_empty_gracefully(normalizer):
    result = normalizer.parse({"hosts": [], "search_results": []}, "unknown.com")
    assert result.open_ports == []
    assert result.attack_surface_score == 0.0


def test_search_results_adds_new_ip(normalizer):
    """IPs found only in search_results (not in hosts) must be included."""
    raw = {
        "hosts": [{"ip_str": "1.2.3.4", "org": "Test", "country_name": "US", "hostnames": [], "data": []}],
        "search_results": [{"ip_str": "5.6.7.8", "port": 80, "product": "", "version": "", "cpe": [], "vulns": {}}],
    }
    result = normalizer.parse(raw, "test.com")
    assert "5.6.7.8" in result.ips


def test_search_results_deduplicates_ip_already_in_hosts(normalizer):
    """An IP already in hosts must not be duplicated when it also appears in search_results."""
    raw = {
        "hosts": [{"ip_str": "1.2.3.4", "org": "Test", "country_name": "US", "hostnames": [], "data": []}],
        "search_results": [{"ip_str": "1.2.3.4", "port": 80, "product": "", "version": "", "cpe": [], "vulns": {}}],
    }
    result = normalizer.parse(raw, "test.com")
    assert result.ips.count("1.2.3.4") == 1
