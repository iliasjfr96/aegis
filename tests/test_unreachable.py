"""A scan against an unreachable host must fail loudly, never report 'clean'."""

import pytest

from aegis.websec import scanner


def test_unreachable_host_raises(monkeypatch):
    from aegis.config import get_settings

    monkeypatch.setattr(
        get_settings(), "target_whitelist", "https://definitely-not-a-real-host-zzz.xyz"
    )
    with pytest.raises(scanner.TargetUnreachableError):
        scanner.run_webscan("https://definitely-not-a-real-host-zzz.xyz")
