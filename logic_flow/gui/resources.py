"""
Resource management for GUI icons and assets.

Provides centralized access to icons and other GUI resources.
"""

from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QFont
from PyQt6.QtCore import QSize, Qt


def get_search_icon(size=16):
    """Get search icon"""
    return _create_icon("🔍", size)


def get_folder_icon(size=16):
    """Get folder icon"""
    return _create_icon("📁", size)


def get_settings_icon(size=16):
    """Get settings icon"""
    return _create_icon("⚙️", size)


def get_bug_icon(size=16):
    """Get bug/debug icon"""
    return _create_icon("🐛", size)


def get_play_icon(size=16):
    """Get play/start icon"""
    return _create_icon("▶️", size)


def get_save_icon(size=16):
    """Get save icon"""
    return _create_icon("💾", size)


def get_clear_icon(size=16):
    """Get clear icon"""
    return _create_icon("🗑️", size)


def get_load_icon(size=16):
    """Get load icon"""
    return _create_icon("📂", size)


def get_sun_icon(size=16):
    """Get sun/light mode icon"""
    return _create_icon("☀️", size)


def get_moon_icon(size=16):
    """Get moon/dark mode icon"""
    return _create_icon("🌙", size)



def get_chart_icon(size=16):
    """Get chart/results icon"""
    return _create_icon("📊", size)


def get_shield_icon(size=16):
    """Get shield/security icon"""
    return _create_icon("🛡️", size)


def get_list_icon(size=16):
    """Get list/log icon"""
    return _create_icon("📜", size)



def _create_icon(emoji, size):
    """Create QIcon from emoji with fallback font support"""
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(0, 0, 0, 0))  # Transparent background

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Try fonts in order of preference for emoji support
    font_families = ["Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji", "Segoe UI Symbol", "Arial Unicode MS"]

    # Find first available font that supports emoji
    selected_font = None
    for family in font_families:
        test_font = QFont(family, size - 4)
        if test_font.exactMatch():  # Check if font family exists
            selected_font = test_font
            break

    # Fallback to system default if no emoji fonts available
    if selected_font is None:
        selected_font = QFont()
        selected_font.setPointSize(size - 4)

    painter.setFont(selected_font)

    # Draw emoji centered
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, emoji)
    painter.end()

    return QIcon(pixmap)
