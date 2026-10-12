"""Creates the four watchers and starts/stops them together with the backend."""
import logging

from app.automation.downloads_watcher import DownloadsWatcher
from app.automation.email_watcher import EmailWatcher
from app.automation.login_monitor import LoginMonitor
from app.automation.windows_logons import WindowsLogonWatcher

logger = logging.getLogger("cyberguard.automation")
WATCHERS = {w.name: w for w in (EmailWatcher(), LoginMonitor(), WindowsLogonWatcher(), DownloadsWatcher())}


def start_all() -> None:
    for w in WATCHERS.values():
        w.start()
    logger.info("Automatic protection started: %s", ", ".join(WATCHERS))


def stop_all() -> None:
    for w in WATCHERS.values():
        w.stop()


def status() -> list[dict]:
    return [w.describe() for w in WATCHERS.values()]
