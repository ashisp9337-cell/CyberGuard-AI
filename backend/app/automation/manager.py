"""Creates the watchers and starts/stops them together with the backend.
The first four run unless switched off; network, dns and website (6 Nov) start OFF and ask permission first."""
import logging

from app.automation.dns_watcher import DnsWatcher
from app.automation.downloads_watcher import DownloadsWatcher
from app.automation.email_watcher import EmailWatcher
from app.automation.login_monitor import LoginMonitor
from app.automation.network_watcher import NetworkWatcher
from app.automation.website_watcher import WebsiteWatcher
from app.automation.windows_logons import WindowsLogonWatcher

logger = logging.getLogger("cyberguard.automation")
WATCHERS = {w.name: w for w in (EmailWatcher(), LoginMonitor(), WindowsLogonWatcher(), DownloadsWatcher(),
                                 NetworkWatcher(), DnsWatcher(), WebsiteWatcher())}


def start_all() -> None:
    for w in WATCHERS.values():
        w.start()
    logger.info("Automatic protection started: %s", ", ".join(WATCHERS))


def stop_all() -> None:
    for w in WATCHERS.values():
        w.stop()


def status() -> list[dict]:
    return [w.describe() for w in WATCHERS.values()]
