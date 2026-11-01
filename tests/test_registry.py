"""Registry integrity.

These tests enforce the central honesty rule of the project: a module may only
claim WORKING if its code exists and its entry callable imports. They also assert
that the PLANNED entries really are unimplemented, so nobody can quietly promote
a roadmap item to "done".
"""

from __future__ import annotations

import pytest

from kingdomx.core import registry as reg
from kingdomx.core.registry import REGISTRY, Status


class TestRegistryShape:
    def test_has_modules(self):
        assert len(REGISTRY.all()) > 40

    def test_keys_are_unique(self):
        keys = [module.key for module in REGISTRY.all()]
        assert len(keys) == len(set(keys))

    def test_every_module_has_a_summary(self):
        for module in REGISTRY.all():
            assert module.summary, f"{module.key} has no summary"

    def test_every_live_module_declares_evidence(self):
        for module in REGISTRY.all():
            if module.status in {Status.PLANNED, Status.UNAVAILABLE}:
                continue
            assert module.verified_by, f"{module.key} claims {module.status.value} with no evidence"

    def test_menu_sections_cover_every_section(self):
        sections = {module.section for module in REGISTRY.all()}
        menu_sections = {key for _n, _t, key in reg.MENU_SECTIONS}
        unknown = sections - menu_sections
        assert not unknown, f"sections with no menu entry: {sorted(unknown)}"


class TestStatusAccuracy:
    def test_no_duplicate_keys(self):
        with pytest.raises(ValueError):
            reg.register("core.platform", "dup", "settings", Status.WORKING, "dup")

    def test_working_modules_resolve(self):
        """The core contract: WORKING implies the callable is importable."""
        broken = []
        for module in REGISTRY.all():
            if module.status is not Status.WORKING:
                continue
            if module.module_path and module.resolve() is None:
                broken.append(module.key)
        assert broken == [], f"WORKING modules whose entry does not import: {broken}"

    def test_planned_modules_are_not_working(self):
        for module in REGISTRY.all():
            assert module.effective_status() is not Status.WORKING or module.status is Status.WORKING

    def test_planned_modules_have_a_roadmap_note(self):
        planned = [m for m in REGISTRY.all() if m.status is Status.PLANNED]
        assert planned, "expected some explicitly PLANNED modules"
        for module in planned:
            assert "ROADMAP" in module.notes, f"{module.key} is PLANNED with no roadmap"

    def test_planned_modules_have_no_module_path(self):
        for module in REGISTRY.all():
            if module.status is Status.PLANNED:
                assert module.module_path is None, (
                    f"{module.key} is PLANNED but names a module path; "
                    "either implement it or drop the path"
                )

    def test_counts_add_up(self):
        counts = REGISTRY.counts()
        assert counts["total"] == len(REGISTRY.all())
        status_total = sum(value for key, value in counts.items() if key != "total")
        assert status_total == counts["total"]


class TestLookup:
    def test_get_unknown_returns_none(self):
        assert REGISTRY.get("does.not.exist") is None

    def test_require_raises(self):
        with pytest.raises(KeyError):
            REGISTRY.require("does.not.exist")

    def test_require_returns_module(self):
        assert REGISTRY.require("core.platform").key == "core.platform"

    def test_search_by_key(self):
        results = REGISTRY.search("platform")
        assert any("platform" in module.key for module in results)

    def test_search_empty_returns_all(self):
        assert len(REGISTRY.search("")) == len(REGISTRY.all())

    def test_search_no_match(self):
        assert REGISTRY.search("zzzzz-nothing-here") == []

    def test_by_section(self):
        grouped = REGISTRY.by_section()
        assert "cyber" in grouped and grouped["cyber"]

    def test_with_status(self):
        working = REGISTRY.with_status(Status.WORKING)
        assert working
        assert all(module.effective_status() is Status.WORKING for module in working)


class TestMenu:
    def test_menu_entries_count(self):
        assert len(reg.menu_entries()) == 25

    def test_menu_numbers_are_two_digits(self):
        for number, _title, _key, _live in reg.menu_entries():
            assert len(number) == 2 and number.isdigit()

    def test_every_section_title_exists(self):
        for _number, _title, key, _live in reg.menu_entries():
            assert key in reg.SECTION_TITLES


class TestSerialisation:
    def test_module_to_dict(self):
        payload = REGISTRY.require("cyber.passwords").to_dict()
        assert payload["key"] == "cyber.passwords"
        assert payload["status"] == "WORKING"
        assert payload["effective_status"] == "WORKING"

    def test_status_labels_are_human_readable(self):
        assert Status.NEEDS_KEY.label == "NEEDS API KEY"
        assert Status.NEEDS_NETWORK.label == "NEEDS NETWORK"
        assert Status.PLANNED.label == "PLANNED"

    def test_is_live_semantics(self):
        assert Status.WORKING.is_live is True
        assert Status.NEEDS_NETWORK.is_live is True
        assert Status.PLANNED.is_live is False
        assert Status.UNAVAILABLE.is_live is False
