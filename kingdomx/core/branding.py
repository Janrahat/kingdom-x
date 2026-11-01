"""KINGDOM X visual identity: crown banner, ASCII wordmark, colour palette.

The banner is deliberately built from a small set of characters so it renders
identically in Kali's GNOME Terminal, Termux, and a plain xterm with no Unicode
support. :func:`banner` falls back to ASCII when the terminal cannot do box
drawing.
"""

from __future__ import annotations

import os
import shutil

#: Royal palette. Rich colour names plus raw hex for the web dashboard.
PALETTE: dict[str, str] = {
    "gold": "#D4AF37",
    "gold_bright": "#F5D061",
    "gold_dim": "#8A6D1F",
    "black": "#0A0A0A",
    "charcoal": "#141414",
    "panel": "#1A1710",
    "text": "#E8E2D0",
    "muted": "#8A8477",
    "online": "#2ECC71",
    "offline": "#7F8C8D",
    "warning": "#E6A700",
    "error": "#E74C3C",
    "info": "#3FA9F5",
}

#: Rich style strings, usable directly as ``[gold]…[/gold]``.
RICH: dict[str, str] = {
    "gold": "bold #D4AF37",
    "gold_bright": "bold #F5D061",
    "gold_dim": "#8A6D1F",
    "panel": "on #1A1710",
    "text": "#E8E2D0",
    "muted": "#8A8477",
    "online": "bold #2ECC71",
    "offline": "#7F8C8D",
    "warning": "bold #E6A700",
    "error": "bold #E74C3C",
    "info": "#3FA9F5",
    "crown": "bold #F5D061",
}

#: The wordmark. Fixed strings — do not regenerate at runtime.
WORDMARK: tuple[str, ...] = (
    " ██╗  ██╗██╗███╗   ██╗ ██████╗ ██████╗  ██████╗ ███╗   ███╗   ██╗  ██╗",
    " ██║ ██╔╝██║████╗  ██║██╔════╝ ██╔══██╗██╔═══██╗████╗ ████║   ╚██╗██╔╝",
    " █████╔╝ ██║██╔██╗ ██║██║  ███╗██║  ██║██║   ██║██╔████╔██║    ╚███╔╝ ",
    " ██╔═██╗ ██║██║╚██╗██║██║   ██║██║  ██║██║   ██║██║╚██╔╝██║    ██╔██╗ ",
    " ██║  ██╗██║██║ ╚████║╚██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║   ██╔╝ ██╗",
    " ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝   ╚═╝  ╚═╝",
)

#: Plain-ASCII fallback for terminals without Unicode box drawing.
WORDMARK_ASCII: tuple[str, ...] = (
    r"  _  __ ___ _  _ ___  ___  ____   __  __ ",
    r" | |/ /|_ _| \| |/ _ \|   \|  _ \  \ \/ / ",
    r" | ' <  | || .` | (_) | |) | |_) |  \  /  ",
    r" |_|\_\|___|_|\_|\___/|___/|____/   /_/   ",
)

#: A small crown, drawn once and reused everywhere.
CROWN: tuple[str, ...] = (
    "        \\   |   /        ",
    "         \\  |  /         ",
    "      .---\\-+-/---.      ",
    "     /  o  \\|/  o  \\     ",
    "    |   .--' '--.   |    ",
    "    |  /  .---.  \\  |    ",
    "    \\_/  /     \\  \\_/    ",
    "        (  ~~~  )        ",
    "         \\_____/         ",
)

CROWN_ASCII: tuple[str, ...] = (
    "      \\  |  /      ",
    "   .---\\-+-/---.   ",
    "  /  *  \\|/  *  \\  ",
    " |    .--' '--.   | ",
    "  \\__/         \\_/ ",
)


def supports_unicode() -> bool:
    """True when the terminal can render box-drawing characters."""
    if os.environ.get("KINGDOMX_ASCII", "").strip().lower() in {"1", "true", "yes", "on"}:
        return False
    encoding = (os.environ.get("PYTHONIOENCODING") or "").lower()
    if "ascii" == encoding or "latin-1" == encoding:
        return False
    try:
        "█╔╝".encode("utf-8")
    except UnicodeEncodeError:  # pragma: no cover
        return False
    return True


def terminal_width(default: int = 96) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except OSError:  # pragma: no cover
        return default


def wordmark(*, ascii_only: bool = False) -> list[str]:
    return list(WORDMARK_ASCII if (ascii_only or not supports_unicode()) else WORDMARK)


def crown(*, ascii_only: bool = False) -> list[str]:
    return list(CROWN_ASCII if (ascii_only or not supports_unicode()) else CROWN)


def banner(
    *,
    subtitle: str = "THE KING OF GLOBAL TECHNOLOGY",
    tagline: str = "ONE PLATFORM. ALL TECHNOLOGIES. UNLIMITED INTELLIGENCE.",
    version: str = "1.0.0",
    ascii_only: bool = False,
    width: int | None = None,
) -> str:
    """Render the full startup banner as plain text (no Rich markup).

    Kept markup-free so it can be written to a log, a README or a terminal that
    does not understand Rich tags.
    """
    use_ascii = ascii_only or not supports_unicode()
    lines: list[str] = []
    rule_char = "-" if use_ascii else "─"
    target_width = width or min(terminal_width(), 96)

    lines.append("+" + rule_char * (target_width - 2) + "+")
    for line in crown(ascii_only=use_ascii):
        lines.append("|" + line[: target_width - 2].center(target_width - 2) + "|")
    lines.append("|" + "".rjust(target_width - 2) + "|")
    for line in wordmark(ascii_only=use_ascii):
        if len(line) > target_width - 2:
            lines.append("|" + line[: target_width - 2] + "|")
        else:
            lines.append("|" + line.center(target_width - 2) + "|")
    lines.append("|" + "".rjust(target_width - 2) + "|")
    lines.append("|" + subtitle.center(target_width - 2) + "|")
    for chunk in _wrap(tagline, target_width - 6):
        lines.append("|" + chunk.center(target_width - 2) + "|")
    lines.append("+" + rule_char * (target_width - 2) + "+")
    lines.append(f"  version {version}   type 'help' for commands   ctrl-c to exit")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    if not words:
        return [""]
    out: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= max(8, width):
            current = candidate
        else:
            if current:
                out.append(current)
            current = word
    if current:
        out.append(current)
    return out


def status_marker(state: str, *, ascii_only: bool = False) -> str:
    """Map a state name to a single-character status glyph."""
    mapping = {
        "online": "●",
        "ok": "●",
        "working": "●",
        "offline": "○",
        "down": "○",
        "warning": "▲",
        "partial": "◐",
        "error": "×",
        "unknown": "·",
    }
    ascii_mapping = {
        "online": "*",
        "ok": "*",
        "working": "*",
        "offline": "o",
        "down": "o",
        "warning": "!",
        "partial": "~",
        "error": "x",
        "unknown": ".",
    }
    table = ascii_mapping if (ascii_only or not supports_unicode()) else mapping
    return table.get(state.lower(), table["unknown"])


def section_header(title: str, *, width: int | None = None, ascii_only: bool = False) -> str:
    """A gold-weight heading with a filled rule, used by reports."""
    use_ascii = ascii_only or not supports_unicode()
    char = "=" if use_ascii else "═"
    total = width or min(terminal_width(), 96)
    text = f" {title.upper()} "
    side = max(0, (total - len(text)) // 2)
    return char * side + text + char * max(0, total - side - len(text))
