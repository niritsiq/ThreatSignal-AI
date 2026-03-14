"""Tests for ShodanClient — checks DNS resolution, Shodan host lookup, and error handling."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from threatsignal.shodan_client.client import ShodanClient


@pytest.fixture
def client():
    return ShodanClient(api_key="test-key")


SHODAN_HOST_RESPONSE = {
    "ip_str": "1.2.3.4",
    "org": "Acme Corp",
    "country_name": "United States",
    "hostnames": ["acme.com"],
    "data": [
        {
            "port": 443,
            "product": "nginx",
            "version": "1.20",
            "cpe": ["cpe:/a:nginx:nginx:1.20"],
            "vulns": {"CVE-2023-1234": {"cvss": 7.5}},
        }
    ],
}


def test_query_domain_returns_hosts(client):
    with patch("socket.gethostbyname_ex", return_value=("acme.com", [], ["1.2.3.4"])):
        with patch.object(client.api, "host", return_value=SHODAN_HOST_RESPONSE):
            with patch.object(client.api, "search", return_value={"matches": []}):
                result = client.query_domain("acme.com")
    assert len(result["hosts"]) == 1
    assert result["hosts"][0]["ip_str"] == "1.2.3.4"


def test_query_domain_includes_org_info(client):
    with patch("socket.gethostbyname_ex", return_value=("acme.com", [], ["1.2.3.4"])):
        with patch.object(client.api, "host", return_value=SHODAN_HOST_RESPONSE):
            with patch.object(client.api, "search", return_value={"matches": []}):
                result = client.query_domain("acme.com")
    assert result["hosts"][0]["org"] == "Acme Corp"
    assert result["hosts"][0]["country_name"] == "United States"


def test_dns_failure_returns_empty_hosts(client):
    import socket as _socket

    with patch("socket.gethostbyname_ex", side_effect=_socket.gaierror("DNS lookup failed")):
        result = client.query_domain("nonexistent-domain-xyz.com")
    assert result["hosts"] == []


def test_shodan_api_error_returns_empty_hosts(client):
    with patch("socket.gethostbyname_ex", return_value=("acme.com", [], ["1.2.3.4"])):
        with patch.object(client.api, "host", side_effect=Exception("API error")):
            with patch.object(client.api, "search", return_value={"matches": []}):
                result = client.query_domain("acme.com")
    # DNS resolved but Shodan lookup failed — hosts list is empty
    assert result["hosts"] == []


def test_multiple_ips_result_in_multiple_host_lookups(client):
    with patch("socket.gethostbyname_ex", return_value=("acme.com", [], ["1.2.3.4", "5.6.7.8"])):
        with patch.object(client.api, "host", return_value=SHODAN_HOST_RESPONSE) as mock_host:
            with patch.object(client.api, "search", return_value={"matches": []}):
                client.query_domain("acme.com")
    assert mock_host.call_count == 2
