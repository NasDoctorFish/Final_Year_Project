"""Visual styling for the desktop app.

Kept separate from app.py so the layout code stays about layout, and so the palette can
be adjusted without touching behaviour.

The look is a dark developer-tool style: slate surfaces, one green accent that means
"run" or "the current selection", and flat cards with a single consistent treatment.
Colours, fonts and the no-emoji-icons rule were set in the UI redesign to suit a security
testing tool. Every text colour pair here was checked against WCAG AA: 4.5:1
for text, 3:1 for control borders and focus rings.
"""

from __future__ import annotations

import os

DARK = {
    "window": "#0f172a",
    "surface": "#1b2336",
    "surface_alt": "#272f42",
    "border": "#334155",
    # Control boundaries need 3:1 against the card behind them; #64748b is 3.3:1.
    "border_strong": "#64748b",
    "text": "#f8fafc",
    "muted": "#94a3b8",
    "primary": "#22c55e",
    "primary_hover": "#4ade80",
    "primary_pressed": "#16a34a",
    # Dark text on the green, 7.8:1. White on this green would only be 2.3:1.
    "primary_text": "#0f172a",
    "disabled_bg": "#1e293b",
    "disabled_text": "#64748b",
    "selection": "#14532d",
    "focus": "#4ade80",
}

# Kept as a fallback only (used if styling fails to apply at all) — the app always
# opens in the dark look above, regardless of the OS theme.
LIGHT = DARK

# Semantic, so they stay constant across themes. Darker than before so the white count
# text on each badge reaches 4.5:1; the old medium (2.4:1) and low (3.5:1) did not.
SEVERITY_COLOURS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#1d4ed8",
    "info": "#475569",
}

# Status text drawn straight onto the dark surfaces: form errors, "saved" notes. The old
# #b00020 and #1b5e20 were only 2.4:1 and 2.3:1 against the window colour.
ERROR_TEXT = "#f87171"
SUCCESS_TEXT = "#4ade80"

# Tile and section names are kept so app.py's properties still match, but every tile now
# shares one treatment. Four competing gradients made no colour mean anything.
TILE_ACCENTS = {name: (DARK["primary"], DARK["primary"])
                for name in ("scan", "assess", "history", "team")}

# Lucide icons (ISC licence), as SVG strokes so they stay sharp at any size and take the
# theme colour, which an emoji cannot.
ICONS = {
    "scan": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "assess": '<rect width="14" height="20" x="5" y="2" rx="2" ry="2"/><path d="M12 18h.01"/>',
    "history": ('<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>'
                '<path d="M3 3v5h5"/><path d="M12 7v5l4 2"/>'),
    "team": ('<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>'
             '<circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/>'
             '<path d="M16 3.13a4 4 0 0 1 0 7.75"/>'),
    "home": ('<path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/>'
             '<path d="M3 10a2 2 0 0 1 .709-1.528l7-5.999a2 2 0 0 1 2.582 0l7 5.999'
             'A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'),
    "shield": ('<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13'
               'V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0'
               'C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>'),
}

# Bundled so the app looks the same on any PC, installed fonts or not. Both are under the
# SIL Open Font License; the licence files sit next to them in gui/fonts/.
FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")


def load_fonts() -> None:
    """Register the bundled fonts with Qt. Missing files fall back to Segoe UI."""
    import glob

    from PySide6.QtGui import QFontDatabase

    for path in glob.glob(os.path.join(FONT_DIR, "*.ttf")):
        QFontDatabase.addApplicationFont(path)


def icon_pixmap(name: str, colour: str, size: int = 32):
    """Render one of ICONS to a QPixmap in the given colour."""
    from PySide6.QtCore import QByteArray, Qt
    from PySide6.QtGui import QPainter, QPixmap
    from PySide6.QtSvg import QSvgRenderer

    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
           f'stroke="{colour}" stroke-width="2" stroke-linecap="round" '
           f'stroke-linejoin="round">{ICONS[name]}</svg>')
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    QSvgRenderer(QByteArray(svg.encode())).render(painter)
    painter.end()
    return pixmap


def is_dark(app) -> bool:  # noqa: ARG001 - kept for API compatibility
    """The dashboard look is always dark, by design — see module docstring."""
    return True


def palette_for(app) -> dict:  # noqa: ARG001
    return DARK


def stylesheet(p: dict) -> str:
    """Build the Qt stylesheet from a palette."""
    # One flat card treatment for every tile. The 2px border is always there (transparent
    # when idle) so hover and focus change colour without shifting the layout.
    tiles = f"""
QPushButton[tileAccent] {{
    background: {p["surface"]};
    border: 2px solid {p["border"]};
    border-radius: 12px;
    text-align: left;
    padding: 0px;
    /* A stylesheet min-height overrides setMinimumSize(), so the generic button rule's
       20px would otherwise squash the card down to a bar. */
    min-height: 128px;
}}
QPushButton[tileAccent]:hover {{ border-color: {p["primary"]}; background: {p["surface_alt"]}; }}
QPushButton[tileAccent]:focus {{ border-color: {p["focus"]}; }}
QPushButton[tileAccent]:pressed {{ background: {p["window"]}; }}
"""
    # Sections no longer get a coloured top edge: with one accent colour, painting it on
    # every card would make green mean "decoration" instead of "run".
    section_accents = ""

    return f"""
/* --- base ---------------------------------------------------------- */
QWidget {{
    background: {p["window"]};
    color: {p["text"]};
    font-family: "IBM Plex Sans", "Segoe UI", Arial, sans-serif;
    font-size: 10pt;
}}

/* Text-only widgets take their parent's background. Without this every label inside a
   card painted the window colour behind itself, leaving dark boxes on the card. */
QLabel, QCheckBox, QRadioButton {{ background: transparent; }}

/* Visible keyboard focus on every control, not only on text fields. */
QPushButton:focus {{ border: 1px solid {p["focus"]}; }}
QCheckBox:focus {{ color: {p["focus"]}; }}
QTabBar::tab:focus {{ color: {p["focus"]}; }}

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
    margin-top: 0px;
    padding: 38px 18px 16px 18px;
    font-weight: 600;
}}
/* Title sits inside the card as its heading, not cut into the border. */
QGroupBox::title {{
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 18px;
    top: 14px;
    padding: 0;
    color: {p["text"]};
    font-size: 10.5pt;
    font-weight: 600;
}}
{section_accents}

/* --- inputs -------------------------------------------------------- */
QLineEdit, QComboBox {{
    background: {p["window"]};
    border: 1px solid {p["border_strong"]};
    border-radius: 8px;
    padding: 8px 10px;
    min-height: 20px;
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
    background: transparent;
    color: {p["text"]};
    border: 1px solid {p["border_strong"]};
    border-radius: 8px;
    padding: 8px 16px;
    min-height: 20px;
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

/* Two-way switch, e.g. "I'm a student" / "I'm setting up a team" at sign-up. */
QPushButton#segment {{
    background: {p["surface_alt"]};
    color: {p["muted"]};
    border: 1px solid {p["border_strong"]};
    border-radius: 0;
    padding: 9px 14px;
}}
QPushButton#segment[segmentPos="left"] {{
    border-top-left-radius: 8px; border-bottom-left-radius: 8px;
}}
QPushButton#segment[segmentPos="right"] {{
    border-top-right-radius: 8px; border-bottom-right-radius: 8px; border-left: none;
}}
QPushButton#segment:hover {{ color: {p["text"]}; }}
QPushButton#segment:checked {{
    background: {p["primary"]};
    color: {p["primary_text"]};
    border-color: {p["primary"]};
}}

/* --- home tiles ------------------------------------------------------ */
{tiles}
QLabel#tileIcon {{ background: transparent; }}
QLabel#tileTitle {{ color: {p["text"]}; font-size: 13pt; font-weight: 700; background: transparent; }}
QLabel#tileSubtitle {{ color: {p["muted"]}; font-size: 9.5pt; background: transparent; }}
QLabel#heroTitle {{
    color: {p["text"]};
    font-size: 22pt;
    font-weight: 800;
    background: transparent;
}}
QLabel#heroSubtitle {{ color: {p["muted"]}; font-size: 10.5pt; background: transparent; }}
QFrame#heroBar {{
    background: {p["border"]};
    border-radius: 1px;
    max-height: 1px;
    min-height: 1px;
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
QLabel#universityHint {{
    background: {p["surface_alt"]};
    border-left: 3px solid {p["primary"]};
    border-radius: 4px;
    padding: 8px 10px;
    font-size: 9pt;
}}
QLabel#fieldLabel {{ color: {p["muted"]}; font-weight: 600; font-size: 9pt; }}
QLabel#accountBadge {{ color: {p["muted"]}; font-size: 9pt; padding: 0; }}

/* --- app shell: sidebar --------------------------------------------- */
QFrame#sidebar {{
    background: {p["surface"]};
    border: none;
    border-right: 1px solid {p["border"]};
}}
QFrame#sidebar QWidget {{ background: transparent; }}
QLabel#brandName {{ color: {p["text"]}; font-size: 13pt; font-weight: 700; }}
QLabel#brandTag {{
    color: {p["muted"]};
    font-family: "JetBrains Mono", "Cascadia Mono", Consolas, monospace;
    font-size: 8pt;
}}
QLabel#navHeading {{
    color: {p["muted"]};
    font-size: 8pt;
    font-weight: 600;
    padding: 0 12px;
}}
QPushButton#navItem {{
    background: transparent;
    color: {p["muted"]};
    border: none;
    border-left: 3px solid transparent;
    border-radius: 0;
    padding: 10px 12px;
    text-align: left;
    font-weight: 500;
}}
QPushButton#navItem:hover {{ color: {p["text"]}; background: {p["surface_alt"]}; }}
QPushButton#navItem:focus {{ color: {p["focus"]}; }}
QPushButton#navItem:checked {{
    color: {p["text"]};
    background: {p["surface_alt"]};
    border-left: 3px solid {p["primary"]};
    font-weight: 600;
}}
QFrame#sidebarDivider {{ background: {p["border"]}; max-height: 1px; min-height: 1px; }}

/* --- app shell: page header ----------------------------------------- */
QLabel#pageTitle {{ color: {p["text"]}; font-size: 18pt; font-weight: 700; }}
QLabel#pageSubtitle {{ color: {p["muted"]}; font-size: 10pt; }}
QTabWidget#pages > QTabBar {{ max-height: 0px; }}

/* --- home: how-it-works steps ---------------------------------------- */
QFrame#stepCard {{
    background: transparent;
    border: 1px solid {p["border"]};
    border-radius: 12px;
}}
QLabel#stepNumber {{
    color: {p["primary"]};
    font-family: "JetBrains Mono", "Cascadia Mono", Consolas, monospace;
    font-size: 9pt;
    font-weight: 600;
}}
QLabel#stepTitle {{ color: {p["text"]}; font-weight: 600; }}
QLabel#stepBody {{ color: {p["muted"]}; font-size: 9pt; }}
QLabel#sectionHeading {{ color: {p["text"]}; font-size: 11pt; font-weight: 600; }}
"""


def apply_theme(app) -> dict:
    """Style the application and return the palette that was used."""
    load_fonts()
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
