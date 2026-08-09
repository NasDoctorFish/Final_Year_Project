"""Visual styling for the desktop app.

Kept separate from app.py so the layout code stays about layout, and so the palette can
be adjusted without touching behaviour.

The stylesheet is generated from a palette rather than written as a literal, because the
app has to look right in both light and dark mode. Qt on Windows follows the system theme,
so a hard-coded light stylesheet would leave dark-mode users with glaring white panels.
Severity colours are deliberately the same in both themes: they carry meaning, and a
reader should not have to relearn them when the theme changes.
"""

from __future__ import annotations

LIGHT = {
    "window": "#f4f5f7",
    "surface": "#ffffff",
    "surface_alt": "#f8f9fb",
    "border": "#dcdfe4",
    "border_strong": "#c3c8ce",
    "text": "#1f2328",
    "muted": "#5f6672",
    "primary": "#0b57d0",
    "primary_hover": "#0a4cb8",
    "primary_pressed": "#08409c",
    "primary_text": "#ffffff",
    "disabled_bg": "#eceef1",
    "disabled_text": "#a0a6ae",
    "selection": "#d6e4ff",
    "focus": "#0b57d0",
}

DARK = {
    "window": "#1b1f24",
    "surface": "#22272e",
    "surface_alt": "#1f242b",
    "border": "#343a42",
    "border_strong": "#454c55",
    "text": "#e4eaf1",
    "muted": "#9aa2ad",
    "primary": "#4c8dff",
    "primary_hover": "#3d7de8",
    "primary_pressed": "#3670cc",
    "primary_text": "#0d1117",
    "disabled_bg": "#2a3038",
    "disabled_text": "#6b737d",
    "selection": "#2d4a7c",
    "focus": "#4c8dff",
}

# Semantic, so they stay constant across themes.
SEVERITY_COLOURS = {
    "critical": "#b3261e",
    "high": "#d93025",
    "medium": "#e08600",
    "low": "#1a73e8",
    "info": "#6b7280",
}


def is_dark(app) -> bool:
    """Decide the theme from the system palette rather than guessing."""
    try:
        from PySide6.QtGui import QPalette

        return app.palette().color(QPalette.Window).lightness() < 128
    except Exception:  # noqa: BLE001 - styling must never stop the app starting
        return False


def palette_for(app) -> dict:
    return DARK if is_dark(app) else LIGHT


def stylesheet(p: dict) -> str:
    """Build the Qt stylesheet from a palette."""
    return f"""
/* --- base ---------------------------------------------------------- */
QWidget {{
    background: {p["window"]};
    color: {p["text"]};
    font-family: "Segoe UI", "Inter", Arial, sans-serif;
    font-size: 10pt;
}}

QMainWindow, QDialog {{ background: {p["window"]}; }}

/* --- tabs ---------------------------------------------------------- */
QTabWidget::pane {{
    background: {p["window"]};
    border: none;
    top: -1px;
}}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent;
    color: {p["muted"]};
    padding: 9px 18px;
    margin-right: 2px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 600;
}}
QTabBar::tab:hover {{ color: {p["text"]}; }}
QTabBar::tab:selected {{
    color: {p["primary"]};
    border-bottom: 2px solid {p["primary"]};
}}

/* --- section cards ------------------------------------------------- */
QGroupBox {{
    background: {p["surface"]};
    border: 1px solid {p["border"]};
    border-radius: 8px;
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

/* --- inputs -------------------------------------------------------- */
QLineEdit, QComboBox {{
    background: {p["surface"]};
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
    background: {p["surface"]};
    color: {p["text"]};
    border: 1px solid {p["border_strong"]};
    border-radius: 6px;
    padding: 7px 14px;
    font-weight: 600;
}}
QPushButton:hover {{ background: {p["surface_alt"]}; border-color: {p["muted"]}; }}
QPushButton:pressed {{ background: {p["disabled_bg"]}; }}
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
    padding: 9px 20px;
    font-size: 10.5pt;
}}
QPushButton#primary:hover {{ background: {p["primary_hover"]}; border-color: {p["primary_hover"]}; }}
QPushButton#primary:pressed {{ background: {p["primary_pressed"]}; }}
QPushButton#primary:disabled {{
    background: {p["disabled_bg"]};
    color: {p["disabled_text"]};
    border-color: {p["border"]};
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
