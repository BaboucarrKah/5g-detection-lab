"""Checks that the lab can see the toolkit it builds on."""

from fiveg_auth.events import EventLog
from fiveg_auth.network import HomeNetwork


def test_toolkit_is_installed():
    assert HomeNetwork("242", "01").events is None


def test_toolkit_has_configurable_clock():
    import inspect
    assert "clock" in inspect.signature(EventLog).parameters
