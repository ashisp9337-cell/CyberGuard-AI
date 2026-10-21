"""CyberGuard backend package."""
import os as _os
import sys as _sys


def _quiet_cpu_count(platform: str, environ, logical_cpus) -> None:
    """Newer Windows 11 has no `wmic`, which joblib/scikit-learn use to count physical CPU cores: they then print a long
    "Could not find the number of physical cores ... WinError 2" warning (harmless, but it looks like a crash in a demo).
    Telling joblib how many cores to use skips that lookup. Half of the logical cores = the physical cores on most
    laptops, and it leaves the PC responsive. A value already set by the user is kept."""
    if platform == "win32" and not environ.get("LOKY_MAX_CPU_COUNT"):
        environ["LOKY_MAX_CPU_COUNT"] = str(max(1, (logical_cpus or 2) // 2))


_quiet_cpu_count(_sys.platform, _os.environ, _os.cpu_count())
