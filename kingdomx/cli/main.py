"""KINGDOM X terminal command center.

Two modes:

``kingdomx``            interactive Rich menu
``kingdomx <command>``  one-shot; every command supports ``--json``

Every menu entry reads its status from :data:`kingdomx.core.registry.REGISTRY`,
so the console cannot advertise something that is not implemented.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Callable

from kingdomx.core import registry as reg
from kingdomx.core.config import Config
from kingdomx.core.platform_detect import current as current_platform
from kingdomx.core.storage import Database
from kingdomx.core.ui import Ui, default_ui

VERSION = "1.0.0"


# --------------------------------------------------------------------------- helpers
def _json_out(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _open_db(config: Config) -> Database:
    return Database(config.db_path)


class App:
    """Holds the objects a command needs."""

    def __init__(self, ui: Ui, config: Config, db: Database) -> None:
        self.ui = ui
        self.config = config
        self.db = db

    # ------------------------------------------------------------- screens
    def splash(self) -> None:
        plat = current_platform()
        self.ui.startup_banner(version=VERSION, platform_label=f"{plat.label} · {plat.arch}")
        counts = reg.REGISTRY.counts()
        self.ui.print(
            f"[bold]modules[/]  "
            f"working [green]{counts.get('WORKING', 0)}[/]  "
            f"network [cyan]{counts.get('NEEDS_NETWORK', 0)}[/]  "
            f"key [cyan]{counts.get('NEEDS_KEY', 0)}[/]  "
            f"authz [yellow]{counts.get('NEEDS_AUTHZ', 0)}[/]  "
            f"planned [dim]{counts.get('PLANNED', 0)}[/]  "
            f"total [bold]{counts.get('total', 0)}[/]"
        )

    def status_board(self, *, section: str | None = None) -> None:
        rows: list[tuple[str, str, str, str, str]] = []
        modules = reg.REGISTRY.all() if not section else reg.REGISTRY.by_section().get(section, [])
        for module in sorted(modules, key=lambda m: (m.section, m.key)):
            status = module.effective_status()
            rows.append(
                (status.marker, module.key, module.title, status.label, module.summary[:64])
            )
        if not rows:
            self.ui.warn(f"no modules registered for section '{section}'")
            return
        self.ui.table(
            ["", "Key", "Module", "Status", "What it does"],
            rows,
            title=reg.SECTION_TITLES.get(section or "", "ALL MODULES"),
        )

    def menu(self) -> None:
        self.ui.newline()
        entries = reg.menu_entries()
        rows = [(num, title, str(live)) for num, title, _key, live in entries]
        rows.append(("00", "EXIT", ""))
        self.ui.table(["#", "CENTER", "LIVE"], rows, title="MAIN MENU")

        choice = self.ui.prompt("Select", default="")
        if not choice:
            return
        if choice == "00":
            raise SystemExit(0)

        match = next((entry for entry in entries if entry[0] == choice), None)
        if match is None:
            self.ui.error(f"'{choice}' is not a menu option")
            return
        _number, title, key, _live = match

        modules = reg.REGISTRY.by_section().get(key, [])
        if not modules:
            self.ui.warn(f"{title} has no registered modules yet.")
            return
        self.ui.rule(title)
        for module in modules:
            status = module.effective_status()
            marker = status.marker
            self.ui.print(f"  {marker} [bold]{module.title}[/] [dim]{status.label}[/]")
            self.ui.muted(f"      {module.summary}")
            if module.notes:
                self.ui.muted(f"      {module.notes}")
            if status is reg.Status.PLANNED:
                self.ui.muted("      not implemented — see the roadmap in docs/ROADMAP.md")

    def interactive(self) -> None:
        self.splash()
        while True:
            try:
                self.menu()
            except SystemExit:
                self.ui.newline()
                self.ui.gold("KINGDOM X signing off.")
                return
            except (KeyboardInterrupt, EOFError):
                self.ui.newline()
                self.ui.gold("Interrupted.")
                return


# --------------------------------------------------------------------------- commands
def cmd_status(app: App, args: argparse.Namespace) -> int:
    modules = reg.REGISTRY.all()
    if args.section:
        modules = reg.REGISTRY.by_section().get(args.section, [])
    payload = {
        "tool": "KINGDOM X",
        "version": VERSION,
        "platform": current_platform().to_dict(),
        "counts": reg.REGISTRY.counts(),
        "modules": [m.to_dict() for m in modules],
    }
    if args.json:
        _json_out(payload)
    else:
        app.splash()
        app.status_board(section=args.section)
    return 0


def cmd_menu(app: App, args: argparse.Namespace) -> int:
    app.interactive()
    return 0


def cmd_selftest(app: App, args: argparse.Namespace) -> int:
    """Check every registered module resolves, plus database and config health."""
    results: list[dict[str, Any]] = []
    for module in reg.REGISTRY.all():
        if module.status is reg.Status.PLANNED:
            continue
        start = time.perf_counter()
        resolved = module.resolve() is not None
        results.append(
            {
                "key": module.key,
                "resolved": resolved,
                "ms": round((time.perf_counter() - start) * 1000, 2),
            }
        )
    failures = [row for row in results if not row["resolved"]]
    db_check = app.db.integrity_check()
    payload = {
        "modules_checked": len(results),
        "resolved": len(results) - len(failures),
        "failures": failures,
        "database": db_check,
        "config": app.config.summary(),
        "ok": not failures and db_check.get("ok", False),
    }
    if args.json:
        _json_out(payload)
    else:
        app.splash()
        if failures:
            app.ui.error(f"{len(failures)} module(s) failed to resolve")
            for row in failures:
                app.ui.muted(f"  {row['key']}")
        else:
            app.ui.success(f"all {len(results)} implemented modules resolve")
        if db_check.get("ok"):
            app.ui.success("database integrity OK")
        else:
            app.ui.error(f"database: {db_check.get('error') or db_check}")
    return 0 if payload["ok"] else 1


def cmd_doctor(app: App, args: argparse.Namespace) -> int:
    from kingdomx.computers.system import health_report

    health = health_report()
    payload = {
        "platform": current_platform().to_dict(),
        "health": health,
        "database": app.db.stats().to_dict(),
        "registry": reg.REGISTRY.counts(),
        "ok": health["verdict"] in {"HEALTHY", "ATTENTION"},
    }
    if args.json:
        _json_out(payload)
    else:
        app.splash()
        snap = health["snapshot"]
        rows = [
            ("Host", snap["hostname"]),
            ("OS", f"{snap['os']['name']} {snap['os']['release']}"),
            ("Arch", snap["os"]["arch"]),
            ("CPU", f"{snap['cpu']['model'][:40]} / {snap['cpu']['cores']} cores"),
            ("Memory", f"{snap['memory']['percent']}% used"),
            ("Uptime", snap["uptime_human"]),
            ("Verdict", health["verdict"]),
        ]
        app.ui.table(["Item", "Value"], rows, title="SYSTEM DIAGNOSTICS")
        for issue in health["issues"]:
            app.ui.warn(f"{issue['level'].upper()} {issue['area']}: {issue['detail']}")
        for disk in health["disks"]:
            app.ui.muted(f"  {disk['mount']:<22} {disk['percent']:>5}% used")
    return 0 if payload["ok"] else 1


def cmd_audit(app: App, args: argparse.Namespace) -> int:
    from kingdomx.cybersecurity.audit import run_audit

    report = run_audit(keys=args.check or None)
    if args.json:
        _json_out(report.to_dict())
    else:
        app.ui.rule("HOST AUDIT")
        for finding in report.sorted_findings():
            style = "green" if finding.passed else "yellow"
            app.ui.print(f"[{style}]{finding.severity.label:<8}[/] {finding.title}")
            if finding.evidence and not finding.passed:
                app.ui.muted(f"         {finding.evidence[:100]}")
        app.ui.newline()
        app.ui.print(f"[bold]verdict:[/] {report.verdict}")
    return 0


def cmd_tools(app: App, args: argparse.Namespace) -> int:
    from kingdomx.cybersecurity.tools import detect_all, inventory_summary

    if args.search:
        from kingdomx.cybersecurity.tools import TOOLS

        needle = args.search.lower()
        rows = [
            (spec.name, spec.category, " & ".join(spec.packages.keys())[:40], spec.license)
            for spec in TOOLS
            if needle in spec.name.lower() or needle in spec.category.lower()
            or needle in spec.description.lower()
        ]
        if args.json:
            _json_out({"query": args.search, "matches": len(rows),
                       "tools": [{"name": r[0], "category": r[1], "license": r[3]} for r in rows]})
        else:
            app.ui.table(["Tool", "Category", "Packages", "Licence"], rows,
                         title=f"TOOL DIRECTORY · '{args.search}' · {len(rows)} match(es)")
        return 0

    detected = detect_all()
    present = [tool for tool in detected if tool.present]
    if args.json:
        _json_out({"summary": inventory_summary(), "tools": [t.to_dict() for t in detected]})
    else:
        rows = [
            (t.spec.name, t.spec.category, t.version or "unknown", t.path or "")
            for t in present
        ]
        app.ui.table(["Tool", "Category", "Version", "Path"], rows,
                     title=f"INSTALLED TOOLS · {len(present)}/{len(detected)}")
        missing = [t.spec.name for t in detected if not t.present]
        if missing:
            app.ui.muted(f"not installed: {', '.join(missing[:12])}"
                         + (f" (+{len(missing) - 12} more)" if len(missing) > 12 else ""))
    return 0


def cmd_dns(app: App, args: argparse.Namespace) -> int:
    from kingdomx.dns.lookup import diagnose, lookup

    if not args.target:
        app.ui.error("a domain is required")
        return 2
    if args.diagnose:
        result = diagnose(args.target)
        if args.json:
            _json_out(result)
        else:
            rows = [(c["name"], "PASS" if c["passed"] else "FAIL", str(c["detail"])[:60])
                    for c in result["checks"]]
            app.ui.table(["Check", "Result", "Detail"], rows,
                         title=f"DNS DIAGNOSE · {args.target}")
        return 0

    records = lookup(args.target, args.type or "A")
    if args.json:
        _json_out(records.to_dict())
    else:
        app.ui.table(
            ["Type", "Value", "TTL"],
            [(rec.type, rec.value[:70], str(rec.ttl)) for rec in records.records],
            title=f"DNS {records.query_type} · {args.target}",
        )
    return 0


def cmd_ip(app: App, args: argparse.Namespace) -> int:
    from kingdomx.ip.intel import classify, geolocate

    if not args.target:
        app.ui.error("an IP address or hostname is required")
        return 2
    info = classify(args.target)
    payload: dict[str, Any] = {"classification": info.to_dict()}
    if args.geo:
        payload["geolocation"] = geolocate(info.address or args.target).to_dict()
    if args.json:
        _json_out(payload)
    else:
        rows = [
            ("Address", str(info.address)),
            ("Scope", info.scope),
            ("Version", f"IPv{info.version}" if info.version else "—"),
            ("Private", str(info.is_private)),
            ("Reverse DNS", info.reverse_dns or "—"),
        ]
        app.ui.table(["Field", "Value"], rows, title="IP CLASSIFICATION")
        if args.geo and payload.get("geolocation"):
            geo = payload["geolocation"]
            app.ui.muted(f"  geo: {geo.get('city') or '—'}, {geo.get('country') or '—'} "
                         f"({geo.get('provider') or 'n/a'}) — approximate only")
    return 0


def cmd_phone(app: App, args: argparse.Namespace) -> int:
    from kingdomx.phone.numbering import coverage_report, parse_number

    if not args.target:
        app.ui.error("a phone number is required")
        return 2
    info = parse_number(args.target, default_country_code=args.country)
    if args.json:
        _json_out({"number": info.to_dict(), "coverage": coverage_report()})
    else:
        rows = [
            ("Country", f"{info.country_name} ({info.country_iso})"),
            ("E.164", info.e164 or "—"),
            ("National", info.formatted_national or "—"),
            ("Line type", info.line_type),
            ("Valid", "yes" if info.ok else "no"),
        ]
        app.ui.table(["Field", "Value"], rows, title="PHONE NUMBER INTELLIGENCE")
        for problem in info.problems:
            app.ui.error(problem)
        for note in info.notes:
            app.ui.muted(f"  {note}")
        app.ui.muted("  A number does not reveal its owner, location or messages.")
    return 0


def cmd_web(app: App, args: argparse.Namespace) -> int:
    from kingdomx.web.app import serve

    app.ui.info(f"starting dashboard on http://{args.host}:{args.port}")
    serve(host=args.host, port=args.port, config=app.config)
    return 0


def cmd_report(app: App, args: argparse.Namespace) -> int:
    from kingdomx.computers.system import health_report
    from kingdomx.cybersecurity.audit import run_audit
    from kingdomx.reports.export import ReportBundle, save_report

    bundle = ReportBundle(platform_label=current_platform().label)
    bundle.add(run_audit())
    path = save_report(bundle, args.output)
    app.ui.success(f"report written to {path}")
    return 0


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kingdomx",
        description="KINGDOM X — ONE PLATFORM. ALL TECHNOLOGIES. UNLIMITED INTELLIGENCE.",
    )
    parser.add_argument("--version", action="version", version=f"KINGDOM X {VERSION}")
    parser.add_argument("--plain", action="store_true", help="disable colours and box drawing")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    sub = parser.add_subparsers(dest="command")

    status = sub.add_parser("status", help="module status board")
    status.add_argument("--section", help="limit to one menu section key")
    status.set_defaults(func=cmd_status)

    sub.add_parser("menu", help="interactive menu (default)").set_defaults(func=cmd_menu)
    sub.add_parser("selftest", help="verify every implemented module resolves").set_defaults(func=cmd_selftest)
    sub.add_parser("doctor", help="system diagnostics and health").set_defaults(func=cmd_doctor)

    audit = sub.add_parser("audit", help="read-only Linux host audit")
    audit.add_argument("--check", action="append", help="run only this check key")
    audit.set_defaults(func=cmd_audit)

    tools = sub.add_parser("tools", help="installed tool detection / directory search")
    tools.add_argument("--search", help="search the tool directory instead of detecting")
    tools.set_defaults(func=cmd_tools)

    dns = sub.add_parser("dns", help="DNS lookup and diagnostics")
    dns.add_argument("target", nargs="?", help="domain name")
    dns.add_argument("--type", help="record type (A, AAAA, MX, TXT, NS, ...)")
    dns.add_argument("--diagnose", action="store_true", help="run the full diagnostic")
    dns.set_defaults(func=cmd_dns)

    ip = sub.add_parser("ip", help="IP classification and geolocation")
    ip.add_argument("target", nargs="?", help="IP address or hostname")
    ip.add_argument("--geo", action="store_true", help="include approximate geolocation")
    ip.set_defaults(func=cmd_ip)

    phone = sub.add_parser("phone", help="phone numbering-plan analysis")
    phone.add_argument("target", nargs="?", help="phone number")
    phone.add_argument("--country", help="default country calling code, e.g. 966")
    phone.set_defaults(func=cmd_phone)

    web = sub.add_parser("web", help="run the web dashboard")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8000)
    web.set_defaults(func=cmd_web)

    report = sub.add_parser("report", help="export a report bundle")
    report.add_argument("--output", default="kingdomx-report.json")
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    ui = Ui.create(plain=getattr(args, "plain", False)) if not sys.stdout.isatty() else default_ui()
    config = Config.load()
    db = Database(config.db_path)
    app = App(ui=ui, config=config, db=db)

    func: Callable[[App, argparse.Namespace], int] = getattr(args, "func", cmd_menu)
    try:
        return func(app, args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - last-resort boundary
        if getattr(args, "json", False):
            _json_out({"ok": False, "error": str(exc), "type": type(exc).__name__})
        else:
            ui.error(f"{type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
