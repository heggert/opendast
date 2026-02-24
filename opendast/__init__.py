"""OpenDAST: AI-Driven Dynamic Application Security Testing Tool."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("opendast")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0-dev"
