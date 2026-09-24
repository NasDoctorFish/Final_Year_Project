"""Visual styling for the desktop app.

Kept separate from app.py so the layout code stays about layout, and so the palette can
be adjusted without touching behaviour.

The look is an Xbox-dashboard style: a near-black chrome, a bright green accent (the
same role Xbox's own accent plays — the one colour that means "the current selection" or
"the primary action"), big bold tab navigation, and a grid of colourful gradient tiles on
the Home tab standing in for a dashboard's app tiles. Unlike the previous theme this no
longer follows the OS light/dark setting: a dashboard look is a deliberate, single
identity, not something that should flip to a white window because Windows is in light
mode. Severity colours are unchanged by this — they carry meaning on their own and a
reader should not have to relearn them.
"""

from __future__ import annotations

DARK = {
    "window": "#0a0c10",
    "surface": "#14171c",
    "surface_alt": "#1b1f26",
    "border": "#262b33",
    "border_strong": "#3a4149",
    "text": "#f3f6fa",
    "muted": "#98a1ac",
    "primary": "#107C10",
    "primary_hover": "#16A616",
    "primary_pressed": "#0c5e0c",
    "primary_text": "#ffffff",
    "disabled_bg": "#1c2026",
    "disabled_text": "#5b6169",
    "selection": "#1f4d2b",
    "focus": "#3BD16F",
}

# Kept as a fallback only (used if styling fails to apply at all) — the app always
# opens in the dashboard-dark look above, regardless of the OS theme.
LIGHT = DARK

# Semantic, so they stay constant across themes.
SEVERITY_COLOURS = {
    "critical": "#c4291f",
    "high": "#e5382d",
    "medium": "#e6952e",
    "low": "#2f8fd8",
    "info": "#8b93a1",
}

# One accent per Home-tab tile / section card, chosen the way an Xbox tile grid uses a
# different colour per app rather than a single flat accent everywhere. Each entry is a
# (start, end) gradient stop pair.
TILE_ACCENTS = {
    "scan": ("#1f6fb2", "#3aa3e8"),
    "assess": ("#6d28d9", "#a166f7"),
    "history": ("#c2680f", "#f2a33d"),
    "team": ("#0c5e0c", "#22c522"),
}


def is_dark(app) -> bool:  # noqa: ARG001 - kept for API compatibility
    """The dashboard look is always dark, by design — see module docstring."""
    return True


def palette_for(app) -> dict:  # noqa: ARG001
    return DARK


def stylesheet(p: dict) -> str:
    """Build the Qt stylesheet from a palette."""
    tiles = "\n".join(
        f"""
QPushButton[tileAccent="{name}"] {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {start}, stop:1 {end});
    border: 2px solid transparent;
    border-radius: 16px;
    text-align: left;
    padding: 0px;
}}
QPushButton[tileAccent="{name}"]:hover {{ border: 2px solid #ffffff; }}
QPushButton[tileAccent="{name}"]:pressed {{ padding-top: 3px; }}
"""
        for name, (start, end) in TILE_ACCENTS.items()
    )
    section_accents = "\n".join(
        f'QGroupBox[accent="{name}"] {{ border-top: 3px solid {start}; }}'
        for name, (start, _end) in TILE_ACCENTS.items()
    )

    return f"""
/* --- base ---------------------------------------------------------- */
QWidget {{
    background: {p["window"]};
    color: {p["text"]};
    font-family: "Segoe UI", "Inter", Arial, sans-serif;
    font-size: 10pt;
}}

QMainWindow, QDialog {{ background: {p["window"]}; }}

/* --- tabs: big bold dashboard-style nav ----------------------------- */
QTabWidget::pane {{
    background: {p["window"]};
    border: none;
    top: -1px;
}}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent;
    color: {p["muted"]};
    padding: 13px 24px;
    margin-right: 6px;
    border: none;
    border-bottom: 3px solid transparent;
    font-weight: 700;
    font-size: 11pt;
}}
QTabBar::tab:hover {{ color: {p["text"]}; }}
QTabBar::tab:selected {{
    color: {p["text"]};
    border-bottom: 3px solid {p["primary"]};
}}

/* --- section cards --------------------------------------------------- */
QGroupBox {{
    background: {p["surface"]};
    border: 1px solid {p["border"]};
    border-radius: 12px;
    margin-top: 14px;
    padding: 14px 14px 12px 14px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 6px;
    color: {p["muted"]};
    font-size: 9pt;
    font-weight: 700;
    text-transform: uppercase;
}}
{section_accents}

/* --- inputs -------------------------------------------------------- */
QLineEdit, QComboBox {{
    background: {p["surface_alt"]};
    border: 1px solid {p["border_strong"]};
    border-radius: 6px;
    padding: 7px 9px;
    selection-background-color: {p["selection"]};
    selection-color: {p["text"]};
}}
QLineEdit:focus, QComboBox:focus {{
    border: 1px solid {p["focus"]};
}}
QLineEdit:disabled, QComboBox:disabled {{
    background: {p["disabled_bg"]};
    color: {p["disabled_text"]};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox QAbstractItemView {{
    background: {p["surface"]};
    border: 1px solid {p["border_strong"]};
    selection-background-color: {p["selection"]};
    selection-color: {p["text"]};
    outline: none;
}}

/* --- buttons ------------------------------------------------------- */
QPushButton {{
    background: {p["surface_alt"]};
    color: {p["text"]};
    border: 1px solid {p["border_strong"]};
    border-radius: 6px;
    padding: 7px 14px;
    font-weight: 600;
}}
QPushButton:hover {{ background: {p["disabled_bg"]}; border-color: {p["muted"]}; }}
QPushButton:pressed {{ background: {p["window"]}; }}
QPushButton:disabled {{
    background: {p["disabled_bg"]};
    color: {p["disabled_text"]};
    border-color: {p["border"]};
}}

/* The one action that runs the scan, so it should be obvious. */
QPushButton#primary {{
    background: {p["primary"]};
    color: {p["primary_text"]};
    border: 1px solid {p["primary"]};
    border-radius: 8px;
    padding: 10px 22px;
    font-size: 10.5pt;
    font-weight: 800;
}}
QPushButton#primary:hover {{ background: {p["primary_hover"]}; border-color: {p["primary_hover"]}; }}
QPushButton#primary:pressed {{ background: {p["primary_pressed"]}; }}
QPushButton#primary:disabled {{
    background: {p["disabled_bg"]};
    color: {p["disabled_text"]};
    border-color: {p["border"]};
}}

/* --- home tiles ------------------------------------------------------ */
{tiles}
QLabel#tileIcon {{ font-size: 28pt; background: transparent; }}
QLabel#tileTitle {{ color: #ffffff; font-size: 13pt; font-weight: 800; background: transparent; }}
QLabel#tileSubtitle {{ color: rgba(255,255,255,0.88); font-size: 9pt; background: transparent; }}
QLabel#heroTitle {{
    color: {p["text"]};
    font-size: 22pt;
    font-weight: 800;
    background: transparent;
}}
QLabel#heroSubtitle {{ color: {p["muted"]}; font-size: 10.5pt; background: transparent; }}
QFrame#heroBar {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {p["primary"]}, stop:1 {p["focus"]});
    border-radius: 2px;
    max-height: 4px;
    min-height: 4px;
}}

/* --- checkboxes ---------------------------------------------------- */
QCheckBox {{ spacing: 8px; padding: 2px 0; }}
QCheckBox:disabled {{ color: {p["disabled_text"]}; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {p["border_strong"]};
    border-radius: 4px;
    background: {p["surface"]};
}}
QCheckBox::indicator:hover {{ border-color: {p["primary"]}; }}
QCheckBox::indicator:checked {{
    background: {p["primary"]};
    border-color: {p["primary"]};
    /* A drawn tick would need an asset; the filled box reads clearly enough. */
}}
QCheckBox::indicator:disabled {{ background: {p["disabled_bg"]}; border-color: {p["border"]}; }}

/* --- results view -------------------------------------------------- */
QTextBrowser {{
    background: {p["surface"]};
    border: 1px solid {p["border"]};
    border-radius: 8px;
    padding: 6px;
}}

/* --- progress ------------------------------------------------------ */
QProgressBar {{
    background: {p["disabled_bg"]};
    border: none;
    border-radius: 3px;
    height: 6px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: {p["primary"]};
    border-radius: 3px;
}}

/* --- chrome -------------------------------------------------------- */
QMenuBar {{ background: {p["window"]}; border-bottom: 1px solid {p["border"]}; }}
QMenuBar::item {{ padding: 6px 12px; background: transparent; }}
QMenuBar::item:selected {{ background: {p["disabled_bg"]}; border-radius: 4px; }}
QMenu {{
    background: {p["surface"]};
    border: 1px solid {p["border_strong"]};
    border-radius: 6px;
    padding: 4px;
}}
QMenu::item {{ padding: 6px 24px 6px 12px; border-radius: 4px; }}
QMenu::item:selected {{ background: {p["selection"]}; color: {p["text"]}; }}
QMenu::item:disabled {{ color: {p["disabled_text"]}; }}
QMenu::separator {{ height: 1px; background: {p["border"]}; margin: 4px 8px; }}

QStatusBar {{
    background: {p["window"]};
    border-top: 1px solid {p["border"]};
    color: {p["muted"]};
}}
QStatusBar::item {{ border: none; }}

QSplitter::handle {{ background: transparent; height: 6px; }}

QScrollBar:vertical {{
    background: transparent; width: 10px; margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {p["border_strong"]}; border-radius: 5px; min-height: 28px;
}}
QScrollBar::handle:vertical:hover {{ background: {p["muted"]}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{
    background: {p["border_strong"]}; border-radius: 5px; min-width: 28px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QToolTip {{
    background: {p["text"]};
    color: {p["surface"]};
    border: none;
    border-radius: 4px;
    padding: 5px 8px;
}}

/* --- named labels -------------------------------------------------- */
QLabel#hint {{ color: {p["muted"]}; font-size: 9pt; }}
QLabel#fieldLabel {{ color: {p["muted"]}; font-weight: 600; font-size: 9pt; }}
QLabel#accountBadge {{ color: {p["muted"]}; padding-right: 8px; }}
"""


def apply_theme(app) -> dict:
    """Style the application and return the palette that was used."""
    p = palette_for(app)
    app.setStyleSheet(stylesheet(p))
    return p


def severity_chips_html(counts: dict, palette: dict) -> str:
    """A row of coloured count badges for a finished run.

    Shows only the severities that actually occurred, so a clean result reads as one
    calm line rather than five zeros the reader has to scan past.
    """
    order = ["critical", "high", "medium", "low", "info"]
    present = [(name, counts.get(name.capitalize(), counts.get(name, 0))) for name in order]
    present = [(name, n) for name, n in present if n]

    if not present:
        return (
            f"<span style='color:{palette['muted']}'>No findings. "
            f"That is not proof the app is safe, only that these checks found nothing."
            f"</span>"
        )

    chips = []
    for name, n in present:
        colour = SEVERITY_COLOURS[name]
        chips.append(
            f"<span style='background:{colour};color:#ffffff;padding:2px 9px;"
            f"border-radius:10px;font-weight:700;font-size:9pt'>"
            f"{n} {name.capitalize()}</span>"
        )
    return "&nbsp;&nbsp;".join(chips)


def empty_state_html(title: str, lines: list[str], palette: dict) -> str:
    """Guidance shown in a results pane before anything has been run.

    An empty white rectangle tells a first-time user nothing about what to do next.
    """
    items = "".join(f"<li style='margin-bottom:6px'>{line}</li>" for line in lines)
    return f"""
    <div style="font-family:'Segoe UI',Arial,sans-serif;padding:18px 20px">
      <h2 style="color:{palette['text']};font-size:14pt;margin:0 0 6px 0">{title}</h2>
      <ul style="color:{palette['muted']};font-size:10pt;padding-left:18px;margin:10px 0 0 0">
        {items}
      </ul>
    </div>
    """
