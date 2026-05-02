"""
Vexa - Enterprise Security Analysis Platform.
"""

try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    # Fallback for Python < 3.8
    try:
        from importlib_metadata import version, PackageNotFoundError
    except ImportError:
        version = lambda _: "unknown"
        PackageNotFoundError = Exception

try:
    __version__ = version("vexa-core")
except (PackageNotFoundError, NameError, ImportError):
    # Fallback for development where the package is not installed
    __version__ = "1.0.56"
