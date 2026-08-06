"""
Phase 38 Unit Tests — Interactive TUI Dashboard & CMD Launcher.
Verifies:
  1. PenFlowTerminalUI initialization.
  2. Menu options rendering.
"""
import pytest
from penflow.cli_menu import PenFlowTerminalUI


def test_penflow_terminal_ui_init():
    tui = PenFlowTerminalUI()
    assert tui is not None


def test_penflow_terminal_ui_render():
    tui = PenFlowTerminalUI()
    # Ensure header and menu display methods execute cleanly without throwing
    tui.display_header()
    tui.display_menu()
