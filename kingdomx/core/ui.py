"""Terminal UI primitives built on Rich.

Everything the operator sees goes through this module so the look stays
consistent: the same panel border, the same status glyphs, the same table
columns. When Rich is unavailable the module degrades to plain text rather than
crashing, which matters on a minimal Termux install.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from kingdomx.core.branding import RICH as C, banner, section_header, status_marker
from kingdomx.core.registry import Status

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - depend on the fallback path
    Console = None  # type: ignore[assignment]
    Panel = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]
    Text = None  # type: ignore[assignment]
    Progress = None  # type: ignore[assignment]
    BarColumn = SpinnerColumn = TextColumn = TimeElapsedColumn = None  # type: ignore[assignment]
    RICH_AVAILABLE = False

STATUS_STYLE: dict[Status, str] = {
    Status.WORKING: C["online"],
    Status.PARTIAL: C["warning"],
    Status.PLANNED: C["muted"],
    Status.UNAVAILABLE: C["error"],
    Status.NEEDS_KEY: C["info"],
    Status.NEEDS_NETWORK: C["info"],
    Status.NEEDS_AUTHZ: C["warning"],
}

SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold #E74C3C",
    "high": "bold #E67E22",
    "medium": "#E6A700",
    "low": "#3FA9F5",
    "info": C["muted"],
    "pass": C["online"],
}


@dataclass
class Ui:
    """A console wrapper that never raises on a dumb terminal."""

    console: Any = None
    plain: bool = False

    @classmethod
    def create(cls, *, plain: bool = False, width: int | None = None) -> "Ui":
        if plain or not RICH_AVAILABLE:
            return cls(console=None, plain=True)
        return cls(
            console=Console(highlight=False, soft_wrap=False, width=width, emoji=False),
            plain=False,
        )

    # ------------------------------------------------------------------ basics
    def print(self, *parts: Any, style: str | None = None) -> None:
        if self.plain:
            text = " ".join(str(part) for part in parts)
            print(_strip_markup(text))
            return
        self.console.print(*parts, style=style)

    def rule(self, title: str = "") -> None:
        if self.plain:
            print(section_header(title) if title else "-" * 60)
            return
        self.console.rule(f"[{C['gold']}]{title}[/]" if title else "", style=C["gold_dim"])

    def newline(self) -> None:
        self.print("")

    def success(self, message: str) -> None:
        self.print(f"[{C['online']}]✔[/] {message}" if not self.plain else f"[OK] {message}")

    def error(self, message: str) -> None:
        self.print(f"[{C['error']}]✖[/] {message}" if not self.plain else f"[ERROR] {message}")

    def warn(self, message: str) -> None:
        self.print(f"[{C['warning']}]▲[/] {message}" if not self.plain else f"[WARN] {message}")

    def info(self, message: str) -> None:
        self.print(f"[{C['info']}]ℹ[/] {message}" if not self.plain else f"[INFO] {message}")

    def muted(self, message: str) -> None:
        self.print(f"[{C['muted']}]{message}[/]" if not self.plain else message)

    def gold(self, message: str) -> None:
        self.print(f"[{C['gold']}]{message}[/]" if not self.plain else message)

    # ------------------------------------------------------------------ banner
    def startup_banner(self, *, version: str = "1.0.0", platform_label: str = "") -> None:
        if self.plain:
            print(banner(version=version))
            if platform_label:
                print(f"platform: {platform_label}")
            return
        art = banner(version=version, width=self._width())
        self.console.print(Text(art, style=C["gold"]))
        if platform_label:
            self.console.print(f"[{C['muted']}]platform[/]  [{C['gold_bright']}]{platform_label}[/]")

    def _width(self) -> int:
        if self.plain:
            return 96
        try:
            return min(self.console.size.width, 100)
        except Exception:  # noqa: BLE001
            return 96

    # ------------------------------------------------------------------ panels
    def panel(self, renderable: Any, *, title: str = "", border: str | None = None) -> None:
        if self.plain:
            if title:
                print(section_header(title))
            print(renderable if isinstance(renderable, str) else str(renderable))
            return
        self.console.print(
            Panel(
                renderable,
                title=f"[{C['gold']}]{title}[/]" if title else None,
                border_style=border or C["gold_dim"],
                padding=(0, 1),
            )
        )

    def status_panel(self, rows: Sequence[tuple[str, str, str]]) -> None:
        """rows: (label, value, state) where state is online/warning/error/offline."""
        if self.plain:
            for label, value, state in rows:
                print(f"  {status_marker(state)} {label:<28} {value}")
            return
        table = Table.grid(padding=(0, 2))
        table.add_column(justify="left")
        table.add_column(justify="left")
        for label, value, state in rows:
            style = {
                "online": C["online"],
                "warning": C["warning"],
                "error": C["error"],
                "partial": C["warning"],
                "offline": C["offline"],
            }.get(state, C["text"])
            table.add_row(
                Text(f"{status_marker(state)} {label}", style=C["muted"]),
                Text(str(value), style=style),
            )
        self.console.print(table)

    # ------------------------------------------------------------------ tables
    def table(
        self,
        columns: Sequence[str],
        rows: Iterable[Sequence[Any]],
        *,
        title: str = "",
        styles: Sequence[str | None] | None = None,
        max_col_width: int = 48,
    ) -> int:
        """Render a table and return the row count actually printed."""
        materialised = [list(row) for row in rows]
        if self.plain:
            if title:
                print(section_header(title))
            print(" | ".join(columns))
            print("-" * 60)
            for row in materialised:
                print(" | ".join(str(cell) for cell in row))
            return len(materialised)

        table = Table(
            title=f"[{C['gold']}]{title}[/]" if title else None,
            header_style=C["gold"],
            border_style=C["gold_dim"],
            show_lines=False,
            expand=False,
            pad_edge=False,
        )
        for column in columns:
            table.add_column(column, overflow="fold", max_width=max_col_width)
        for row in materialised:
            rendered: list[Any] = []
            for index, cell in enumerate(row):
                style = styles[index] if styles and index < len(styles) else None
                rendered.append(Text(str(cell), style=style) if style else str(cell))
            table.add_row(*rendered)
        if not materialised:
            self.console.print(f"[{C['muted']}](no rows)[/]")
            return 0
        self.console.print(table)
        return len(materialised)

    def kv_table(self, pairs: Sequence[tuple[str, Any]], *, title: str = "") -> None:
        if self.plain:
            if title:
                print(section_header(title))
            for key, value in pairs:
                print(f"  {key:<26} {value}")
            return
        table = Table.grid(padding=(0, 2))
        table.add_column(style=C["muted"], justify="right")
        table.add_column(style=C["text"])
        for key, value in pairs:
            table.add_row(str(key), str(value))
        if title:
            self.console.print(f"[{C['gold']}]{title}[/]")
        self.console.print(table)

    def module_table(self, modules: Sequence[Any], *, title: str = "") -> None:
        """Render registry modules with their honest status."""
        rows = []
        for module in modules:
            status = module.effective_status()
            rows.append([status.marker, module.title, status.label, module.summary])
        styles = [None, C["text"], None, C["muted"]]
        if self.plain:
            self.table(["", "MODULE", "STATUS", "SUMMARY"], rows, title=title)
            return
        table = Table(
            title=f"[{C['gold']}]{title}[/]" if title else None,
            header_style=C["gold"],
            border_style=C["gold_dim"],
            expand=False,
        )
        table.add_column("", width=2)
        table.add_column("MODULE", style=C["text"], overflow="fold", max_width=38)
        table.add_column("STATUS", overflow="fold", max_width=22)
        table.add_column("SUMMARY", style=C["muted"], overflow="fold", max_width=52)
        for module in modules:
            status = module.effective_status()
            table.add_row(
                Text(status.marker, style=STATUS_STYLE.get(status, C["text"])),
                module.title,
                Text(status.label, style=STATUS_STYLE.get(status, C["muted"])),
                module.summary,
            )
        self.console.print(table)

    # ------------------------------------------------------------------ progress
    def progress(self, description: str = "working"):
        """Context manager yielding an object with ``.advance(n)`` and ``.update``."""
        ui = self

        class _PlainProgress:
            def __enter__(self_inner):
                print(f"... {description}")
                return self_inner

            def __exit__(self_inner, *exc):
                return False

            def advance(self_inner, amount: int = 1) -> None:
                pass

            def update(self_inner, **kwargs: Any) -> None:
                pass

        if self.plain or Progress is None:
            return _PlainProgress()

        return Progress(
            SpinnerColumn(style=C["gold"]),
            TextColumn("[{task.description}]"),
            BarColumn(bar_width=32, complete_style=C["gold"], finished_style=C["online"]),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=ui.console,
            transient=True,
        )

    def prompt(self, label: str, *, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        if self.plain:
            raw = input(f"{label}{suffix}: ").strip()
        else:
            try:
                raw = self.console.input(f"[{C['gold']}]{label}[/][{C['muted']}]{suffix}[/]: ").strip()
            except (EOFError, KeyboardInterrupt):
                return default
        return raw or default

    def confirm(self, question: str, *, default: bool = False) -> bool:
        marker = "Y/n" if default else "y/N"
        answer = self.prompt(f"{question} ({marker})").strip().lower()
        if not answer:
            return default
        return answer in {"y", "yes", "1", "true", "ok"}


def _strip_markup(text: str) -> str:
    """Remove Rich ``[style]`` tags for the plain-text fallback."""
    out: list[str] = []
    depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == "[":
            depth += 1
            index += 1
            continue
        if char == "]" and depth:
            depth -= 1
            index += 1
            continue
        if not depth:
            out.append(char)
        index += 1
    return "".join(out)


def severity_style(severity: str) -> str:
    return SEVERITY_STYLE.get((severity or "").lower(), C["text"])


def plain_ui() -> Ui:
    """A UI that writes unadorned text — used by tests and piping."""
    return Ui.create(plain=True)


def default_ui() -> Ui:
    """A UI that matches the real terminal capability."""
    plain = not sys.stdout.isatty() or not RICH_AVAILABLE
    return Ui.create(plain=plain)
