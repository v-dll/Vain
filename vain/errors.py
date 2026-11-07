"""Exception types. The CLI maps these to exit codes (ConfigError=2, other VainError=3)."""


class VainError(Exception):
    """Base class for expected, user-presentable failures."""


class ConfigError(VainError):
    """Bad user input or configuration (exit code 2)."""


class TargetError(ConfigError):
    """A scan target is invalid or unsafe."""


class PluginConfigError(ConfigError):
    """A plugin was given bad options (missing file, bad URL, missing API key...)."""


class ScanError(VainError):
    """Nmap is missing, failed, or timed out."""


class ParseError(VainError):
    """Nmap XML could not be parsed safely."""
