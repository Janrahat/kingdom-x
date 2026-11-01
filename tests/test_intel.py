"""Intelligence modules: IP, DNS parsing, domains, websites, phone, devices, globaltech."""

from __future__ import annotations

import pytest

from kingdomx.devices.catalog import (
    ANDROID_VERSIONS,
    DEVICE_MODELS,
    MANUFACTURERS,
    catalog_summary,
    classify_device,
    find_android_version,
    find_manufacturer,
    find_model,
    parse_user_agent_device,
)
from kingdomx.dns.lookup import (
    ALL_TYPES,
    PUBLIC_RESOLVERS,
    available_backends,
    dnspython_available,
    parse_resolv_conf,
)
from kingdomx.domains.rdap import homograph_check, registrars_note
from kingdomx.globaltech.intel import (
    AI_PROVIDERS,
    CLOUD_PROVIDERS,
    COUNTRY_INFRASTRUCTURE,
    DATASETS,
    LANGUAGES,
    ai_providers_reference,
    dataset_info,
    internet_exchange_points,
    list_datasets,
    lookup_country,
    registry_summary,
)
from kingdomx.ip.intel import classify, is_private, local_interfaces
from kingdomx.phone.numbering import (
    PLANS,
    coverage_report,
    parse_number,
    supported_countries,
    validate_e164,
)
from kingdomx.websites.audit import FINGERPRINTS, fingerprint


# --------------------------------------------------------------------- IP
class TestIpClassification:
    def test_public_address(self):
        info = classify("8.8.8.8")
        assert info.address == "8.8.8.8"
        assert info.is_private is False

    def test_private_address(self):
        info = classify("192.168.1.5")
        assert info.is_private is True

    def test_loopback(self):
        assert classify("127.0.0.1").is_private is True

    def test_ipv6(self):
        info = classify("2001:4860:4860::8888")
        assert info.version == 6

    def test_cgnat_scope(self):
        info = classify("100.64.0.1")
        assert info.is_private is True

    def test_invalid_address_raises(self):
        with pytest.raises(Exception):
            classify("999.999.999.999")

    def test_is_private_helper(self):
        assert is_private("10.0.0.1") is True
        assert is_private("1.1.1.1") is False

    def test_local_interfaces_returns_a_list(self):
        assert isinstance(local_interfaces(), list)


# --------------------------------------------------------------------- DNS
class TestDns:
    def test_record_types_declared(self):
        assert "A" in ALL_TYPES and "MX" in ALL_TYPES

    def test_public_resolvers(self):
        assert "1.1.1.1" in PUBLIC_RESOLVERS.values() or "cloudflare" in str(PUBLIC_RESOLVERS).lower()

    def test_available_backends_never_empty(self):
        # The socket backend is always present, so this can be asserted offline.
        assert available_backends()

    def test_dnspython_flag_is_boolean(self):
        assert isinstance(dnspython_available(), bool)

    def test_parse_resolv_conf_missing_file(self, tmp_path):
        assert parse_resolv_conf(str(tmp_path / "nope.conf")) == []

    def test_parse_resolv_conf(self, tmp_path):
        path = tmp_path / "resolv.conf"
        path.write_text("nameserver 1.1.1.1\nnameserver 8.8.8.8\n", encoding="utf-8")
        assert parse_resolv_conf(str(path)) == ["1.1.1.1", "8.8.8.8"]


# --------------------------------------------------------------------- domains
class TestHomograph:
    def test_plain_ascii_domain_is_clean(self):
        result = homograph_check("example.com")
        assert result["risky"] is False
        assert result["is_idn"] is False

    def test_punycode_domain_flagged(self):
        result = homograph_check("xn--80ak6aa92e.com")
        assert result["is_idn"] is True
        assert result["risky"] is True

    def test_mixed_script_flagged(self):
        # Cyrillic 'а' inside an otherwise Latin label.
        result = homograph_check("pаypal.com")
        assert result["risky"] is True
        assert result["mixed_script_labels"]

    def test_plain_ascii_lookalike_is_not_mixed_script(self):
        # No non-ASCII at all, so there is no script mixing to report.
        assert homograph_check("paypa1.com")["mixed_script_labels"] == []

    def test_skeleton_reveals_the_spoof(self):
        result = homograph_check("pаypal.com")
        assert result["skeleton"] == "paypal.com"
        assert result["skeleton_differs_from_latin"] is True

    def test_registrars_note_is_text(self):
        assert isinstance(registrars_note(), str) and registrars_note()


# --------------------------------------------------------------------- websites
class TestFingerprint:
    def test_signature_table_populated(self):
        assert len(FINGERPRINTS) >= 40

    def test_every_signature_declares_a_source_and_pattern(self):
        for sig in FINGERPRINTS:
            assert sig.source in {"header", "body", "cookie_name", "title"}, sig.name
            assert sig.pattern, sig.name

    def test_detects_nginx_from_server_header(self):
        found = fingerprint(headers={"server": "nginx/1.24.0"}, body="")
        names = {match["name"].lower() for match in found}
        assert any("nginx" in name for name in names)

    def test_detects_wordpress_from_body(self):
        body = '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
        found = fingerprint(headers={}, body=body)
        assert any("wordpress" in match["name"].lower() for match in found)

    def test_no_false_positive_on_empty_input(self):
        assert fingerprint(headers={}, body="") == []

    def test_reports_evidence_for_every_match(self):
        body = '<script src="/wp-includes/js/jquery.js"></script>'
        found = fingerprint(headers={}, body=body)
        assert found
        assert all(match.get("evidence") for match in found)

    def test_matches_carry_a_category(self):
        found = fingerprint(headers={"server": "nginx/1.24.0"}, body="")
        assert all(match.get("category") for match in found)


# --------------------------------------------------------------------- phone
class TestPhoneNumbering:
    def test_saudi_mobile(self):
        info = parse_number("+966501234567")
        assert info.ok is True
        assert info.country_iso == "SA"
        assert info.line_type == "mobile"

    def test_saudi_landline(self):
        info = parse_number("+966112345678")
        assert info.line_type == "fixed"

    def test_uae_mobile(self):
        info = parse_number("+971501234567")
        assert info.ok and info.line_type == "mobile"

    def test_pakistan_mobile(self):
        info = parse_number("+923001234567")
        assert info.ok and info.line_type == "mobile"

    def test_india_mobile(self):
        info = parse_number("+919876543210")
        assert info.ok and info.line_type == "mobile"

    def test_uk_mobile(self):
        info = parse_number("+447700900123")
        assert info.ok and info.line_type == "mobile"

    def test_formatting(self):
        info = parse_number("+966501234567")
        assert info.e164 == "+966501234567"
        assert info.formatted_international
        assert info.rfc3966 == "tel:+966501234567"

    def test_too_short_rejected(self):
        assert parse_number("12345").ok is False

    def test_too_long_rejected(self):
        assert parse_number("+1" + "2" * 20).ok is False

    def test_empty_rejected(self):
        assert parse_number("").ok is False

    def test_wrong_length_for_plan(self):
        info = parse_number("+96650123456")  # 8 national digits, SA needs 9
        assert info.ok is False
        assert info.problems

    def test_arabic_indic_digits_accepted(self):
        info = parse_number("+٩٦٦٥٠١٢٣٤٥٦٧")
        assert info.ok is True

    def test_trunk_prefix_with_default_country(self):
        info = parse_number("0501234567", default_country_code="966")
        assert info.ok is True
        assert info.e164 == "+966501234567"

    def test_validate_e164(self):
        ok, value = validate_e164("+966501234567")
        assert ok is True and value == "+966501234567"

    def test_coverage_is_honest(self):
        report = coverage_report()
        assert report["plans_with_structure"] == len(PLANS)
        assert "subscriber name or identity" in report["cannot_determine"]

    def test_supported_countries(self):
        countries = supported_countries()
        assert len(countries) == len(PLANS)
        assert any(c["iso"] == "SA" for c in countries)


# --------------------------------------------------------------------- devices
class TestDeviceCatalog:
    def test_manufacturers_present(self):
        assert len(MANUFACTURERS) >= 15

    def test_models_present(self):
        assert len(DEVICE_MODELS) >= 14

    def test_android_versions(self):
        assert len(ANDROID_VERSIONS) >= 8

    def test_every_manufacturer_has_a_security_page(self):
        for row in MANUFACTURERS:
            assert row["security_page"].startswith("http")

    def test_find_manufacturer(self):
        assert find_manufacturer("samsung")
        assert find_manufacturer("android")

    def test_find_model(self):
        assert find_model("pixel")
        assert find_model("gibberish-model-xyz") == []

    def test_find_android_version(self):
        row = find_android_version("14")
        assert row is not None and row["api"] == 34

    def test_classify_explicit_category(self):
        assert classify_device(category="router")["category"] == "router"

    def test_classify_unknown_category(self):
        assert classify_device(category="spaceship")["category"] == "unknown"

    def test_classify_iphone_ua(self):
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
        assert classify_device(user_agent=ua)["category"] == "mobile"

    def test_classify_ipad_ua(self):
        ua = "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15"
        assert classify_device(user_agent=ua)["category"] == "tablet"

    def test_classify_desktop_ua(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        assert classify_device(user_agent=ua)["category"] == "desktop"

    def test_classify_empty_ua(self):
        assert classify_device(user_agent="")["category"] == "unknown"

    def test_parse_user_agent_extracts_os_and_browser(self):
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        info = parse_user_agent_device(ua)
        assert info["os"] == "Windows"
        assert info["browser"] == "Chrome"

    def test_parse_user_agent_android(self):
        ua = (
            "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        )
        info = parse_user_agent_device(ua)
        assert info["os"] == "Android"

    def test_catalog_summary_counts(self):
        summary = catalog_summary()
        assert summary["manufacturers"] == len(MANUFACTURERS)
        assert summary["models"] == len(DEVICE_MODELS)
        assert "cannot enumerate private device inventories" in summary["policy"]


# --------------------------------------------------------------------- globaltech
class TestGlobalTech:
    def test_datasets_have_full_provenance(self):
        for key, meta in DATASETS.items():
            for field in ("title", "source", "as_of", "coverage", "confidence", "limitations"):
                assert meta.get(field), f"{key} is missing '{field}'"

    def test_list_datasets(self):
        datasets = list_datasets()
        assert len(datasets) == len(DATASETS)
        for row in datasets:
            assert "rows" in row

    def test_dataset_info(self):
        info = dataset_info("country_infrastructure")
        assert info["rows"]
        assert info["meta"]["source"]

    def test_dataset_info_unknown_raises(self):
        with pytest.raises(KeyError):
            dataset_info("nope")

    def test_lookup_country_by_iso(self):
        result = lookup_country("SA")
        assert result["matches"][0]["name"] == "Saudi Arabia"

    def test_lookup_country_by_calling_code(self):
        result = lookup_country("+966")
        assert result["matches"][0]["iso"] == "SA"

    def test_lookup_country_by_name(self):
        assert lookup_country("pakistan")["matches"]

    def test_lookup_country_empty_raises(self):
        with pytest.raises(ValueError):
            lookup_country("")

    def test_country_rows_are_well_formed(self):
        for row in COUNTRY_INFRASTRUCTURE:
            assert row["calling_code"].startswith("+")
            assert row["tld"].startswith(".")
            assert row["rir"]

    def test_cloud_rows(self):
        for row in CLOUD_PROVIDERS:
            assert row["docs"].startswith("http")
            assert row["note"], f"{row['name']} claims a region count with no caveat"

    def test_ai_provider_rows(self):
        for row in AI_PROVIDERS:
            assert row["docs"].startswith("http")
            assert row["kingdomx_provider"]

    def test_language_rows(self):
        assert any(row["name"] == "Python" for row in LANGUAGES)

    def test_internet_exchange_points(self):
        result = internet_exchange_points()
        assert result["count"] > 0
        assert len(result["rows"]) == result["count"]
        assert "not the global ixp list" in result["note"].lower()
        assert result["meta"]["source"]

    def test_ai_providers_reference_does_not_claim_availability(self):
        result = ai_providers_reference()
        assert "availability comes from a live health check" in result["note"].lower()

    def test_registry_summary_policy_present(self):
        summary = registry_summary()
        assert summary["total_rows"] > 0
        assert summary["policy"]
