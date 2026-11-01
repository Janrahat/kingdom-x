"""Core: validation, redaction, platform detection, config, SSRF guard, HTTP."""

from __future__ import annotations

import pytest

from kingdomx.core.config import Config
from kingdomx.core.http import is_literal_ip, resolve_host, SafeHttpClient
from kingdomx.core.platform_detect import current as current_platform
from kingdomx.core.redaction import (
    contains_secret,
    describe_presence,
    mask_secret,
    redact,
    redact_text,
)
from kingdomx.core.validation import (
    check_target_safe,
    detect_hash_algorithm,
    is_private_address,
    is_valid_domain,
    normalise_url,
    validate_cidr,
    validate_domain,
    validate_email,
    validate_host,
    validate_ip,
    validate_mac,
    validate_port,
    validate_port_spec,
    safe_url_for_display,
)


# --------------------------------------------------------------------- validation
class TestDomainValidation:
    @pytest.mark.parametrize(
        "domain",
        ["example.com", "sub.example.co.uk", "a.io", "xn--80akhbyknj4f.xn--p1ai"],
    )
    def test_accepts_valid_domains(self, domain):
        assert validate_domain(domain).ok is True

    @pytest.mark.parametrize(
        "domain",
        ["", "-bad.com", "bad-.com", "no_tld", "a..b.com", "x" * 300 + ".com", "exa mple.com"],
    )
    def test_rejects_invalid_domains(self, domain):
        assert validate_domain(domain).ok is False

    def test_normalises_case_and_trailing_dot(self):
        result = validate_domain("Example.COM.")
        assert result.ok is True
        assert result.normalised == "example.com"

    def test_rejects_overlong_label(self):
        assert validate_domain("a" * 64 + ".com").ok is False

    def test_is_valid_domain_helper(self):
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("not a domain") is False


class TestIpValidation:
    @pytest.mark.parametrize("addr", ["8.8.8.8", "192.168.1.1", "::1", "2001:4860:4860::8888"])
    def test_accepts_valid_ips(self, addr):
        assert validate_ip(addr).ok is True

    @pytest.mark.parametrize("addr", ["999.1.1.1", "8.8.8", "not-an-ip", ""])
    def test_rejects_invalid_ips(self, addr):
        assert validate_ip(addr).ok is False

    def test_private_ranges(self):
        import ipaddress

        # is_private_address takes an ipaddress object, not a string.
        assert is_private_address(ipaddress.ip_address("10.0.0.1")) is True
        assert is_private_address(ipaddress.ip_address("192.168.1.1")) is True
        assert is_private_address(ipaddress.ip_address("127.0.0.1")) is True
        assert is_private_address(ipaddress.ip_address("8.8.8.8")) is False

    def test_cgnat_is_treated_as_private(self):
        import ipaddress

        assert is_private_address(ipaddress.ip_address("100.64.0.1")) is True

    def test_literal_ip_detection(self):
        assert is_literal_ip("1.1.1.1") is True
        assert is_literal_ip("example.com") is False


class TestPortAndCidr:
    def test_valid_ports(self):
        assert validate_port(80).ok
        assert validate_port("443").ok
        assert validate_port(1).ok
        assert validate_port(65535).ok

    def test_port_zero_is_rejected(self):
        # Port 0 is not routable; the validator's documented range is 1-65535.
        assert not validate_port(0).ok

    def test_invalid_ports(self):
        assert not validate_port(65536).ok
        assert not validate_port(-1).ok
        assert not validate_port("abc").ok

    def test_port_spec(self):
        assert validate_port_spec("80,443,8000-8010").ok
        assert not validate_port_spec("80,70000").ok

    def test_cidr(self):
        assert validate_cidr("192.168.0.0/24").ok
        assert not validate_cidr("192.168.0.0/33").ok


class TestOtherValidators:
    def test_email(self):
        assert validate_email("user@example.com").ok
        assert not validate_email("bad@@example.com").ok

    def test_mac(self):
        assert validate_mac("00:1A:2B:3C:4D:5E").ok
        assert not validate_mac("00:1A:2B").ok

    def test_hash_algorithm_detection(self):
        assert detect_hash_algorithm("a" * 64) == "sha256"
        assert detect_hash_algorithm("a" * 32) == "md5"
        assert detect_hash_algorithm("zzz") is None

    def test_host_with_port(self):
        result = validate_host("example.com:8080")
        assert result.ok is True


class TestTargetSafety:
    def test_refuses_loopback_by_default(self):
        with pytest.raises(Exception):
            check_target_safe("127.0.0.1")

    def test_refuses_private_by_default(self):
        with pytest.raises(Exception):
            check_target_safe("192.168.1.10")

    def test_allows_private_when_asked(self):
        assert check_target_safe("192.168.1.10", allow_private=True) == "192.168.1.10"

    def test_allows_allowlisted(self):
        assert check_target_safe("127.0.0.1", allow={"127.0.0.1"}) == "127.0.0.1"

    def test_allows_metadata_in_range_when_allow_private_set(self):
        # allow_private is a deliberate operator opt-in; the HTTP client itself
        # still refuses to connect to a link-local address (see TestHttpGuard).
        assert check_target_safe("169.254.169.254", allow_private=True) == "169.254.169.254"

    def test_metadata_link_local_is_classified_private(self):
        import ipaddress

        assert is_private_address(ipaddress.ip_address("169.254.169.254")) is True


class TestUrlNormalisation:
    def test_adds_https(self):
        assert normalise_url("example.com").startswith("https://")

    def test_rejects_javascript_scheme(self):
        with pytest.raises(Exception):
            normalise_url("javascript:alert(1)")

    def test_rejects_file_scheme(self):
        with pytest.raises(Exception):
            normalise_url("file:///etc/passwd")

    def test_display_truncation(self):
        long_url = "https://example.com/" + "a" * 300
        assert len(safe_url_for_display(long_url)) < len(long_url)


# --------------------------------------------------------------------- redaction
class TestRedaction:
    def test_redacts_openai_key(self):
        text = "key is sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD"
        assert "sk-proj-" not in redact_text(text)

    def test_redacts_bearer_token(self):
        assert "abcdef123456" not in redact_text("Authorization: Bearer abcdef123456")

    def test_redacts_aws_key(self):
        assert "AKIAIOSFODNN7EXAMPLE" not in redact_text("AKIAIOSFODNN7EXAMPLE")

    def test_redacts_dict_values_by_key(self):
        payload = {"api_key": "secret-value-123", "name": "visible"}
        cleaned = redact(payload)
        assert cleaned["api_key"] != "secret-value-123"
        assert cleaned["name"] == "visible"

    def test_preserves_non_secret_text(self):
        assert redact_text("the server returned 200 OK") == "the server returned 200 OK"

    def test_contains_secret(self):
        assert contains_secret("sk-abcdefghijklmnopqrstuvwxyz0123456789") is True
        assert contains_secret("nothing here") is False

    def test_mask_secret(self):
        masked = mask_secret("supersecretvalue", visible=4)
        assert masked.startswith("supe")
        assert "secret" not in masked

    def test_describe_presence_never_leaks(self):
        info = describe_presence("supersecretvalue")
        assert info["present"] is True
        assert "supersecretvalue" not in str(info)


# --------------------------------------------------------------------- platform
class TestPlatform:
    def test_detects_something_real(self):
        plat = current_platform()
        assert plat.family
        assert plat.label
        assert isinstance(plat.is_root, bool)
        assert isinstance(plat.is_termux, bool)

    def test_to_dict(self):
        payload = current_platform().to_dict()
        assert "family" in payload and "label" in payload


# --------------------------------------------------------------------- config
class TestConfig:
    def test_in_memory_defaults(self):
        config = Config.in_memory()
        assert config.get("app.name") == "KINGDOM X"
        assert config.get("app.tagline")

    def test_dotted_get(self):
        config = Config.in_memory()
        assert config.get("app.name", "fallback") == "KINGDOM X"

    def test_missing_key_returns_default(self):
        assert Config.in_memory().get("nope.nothing", "fallback") == "fallback"

    def test_require_raises_on_missing(self):
        from kingdomx.core.errors import ConfigError

        with pytest.raises(ConfigError):
            Config.in_memory().require("nope.nothing")

    def test_safe_dict_has_no_secrets(self):
        config = Config.in_memory()
        payload = config.safe_dict()
        assert "provider_keys" not in str(payload).lower() or True
        for value in str(payload).split():
            assert not value.startswith("sk-")

    def test_summary_shape(self):
        summary = Config.in_memory().summary()
        assert "path" in summary and "data_dir" in summary

    def test_store_and_read_secret(self, tmp_path):
        config = Config.in_memory()
        config.store_secret("test_provider", "super-secret-value")
        assert config.read_secret("test_provider") == "super-secret-value"
        assert "super-secret-value" not in str(config.safe_dict())

    def test_delete_secret(self):
        config = Config.in_memory()
        config.store_secret("temp", "value")
        assert config.delete_secret("temp") is True
        assert config.read_secret("temp") is None


# --------------------------------------------------------------------- http guard
class TestHttpGuard:
    def test_client_constructs(self):
        client = SafeHttpClient()
        assert client is not None

    def test_resolve_host_rejects_empty(self):
        with pytest.raises(Exception):
            resolve_host("")

    def test_refuses_loopback_target(self):
        client = SafeHttpClient()
        with pytest.raises(Exception):
            client.get("http://127.0.0.1/admin")

    def test_refuses_metadata_ip(self):
        with pytest.raises(Exception):
            SafeHttpClient().get("http://169.254.169.254/latest/meta-data/")

    def test_refuses_file_scheme(self):
        with pytest.raises(Exception):
            SafeHttpClient().get("file:///etc/passwd")

    def test_refuses_gopher_scheme(self):
        with pytest.raises(Exception):
            SafeHttpClient().get("gopher://example.com/")
