"""Foundation and configuration unit tests for jwtsec."""

import os
from unittest.mock import patch

from jwtsec import __version__
from jwtsec.config.settings import Settings, get_settings


def test_package_metadata() -> None:
    """Verify package version string."""
    assert __version__ == "0.1.0"


def test_settings_defaults() -> None:
    """Verify default runtime settings."""
    settings = get_settings()
    assert settings.app_name == "JWT Security Analyzer"
    assert settings.version == "0.1.0"
    assert settings.environment == "development"
    assert settings.allow_none_algorithm is False
    assert settings.enable_bruteforce is True
    assert settings.clock_skew_leeway_seconds == 60
    assert settings.lab_port == 8082


def test_settings_env_override() -> None:
    """Verify environment variables override configuration."""
    with patch.dict(
        os.environ,
        {
            "JWTSEC_ENVIRONMENT": "production",
            "JWTSEC_ALLOW_NONE_ALGORITHM": "true",
            "JWTSEC_LAB_PORT": "9090",
        },
    ):
        settings = Settings()
        assert settings.environment == "production"
        assert settings.allow_none_algorithm is True
        assert settings.lab_port == 9090
