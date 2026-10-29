"""Separate-process reader for Windows .evtx files (python-evtx, pure Python): path in, event XML out.

Started by windows_events.evtx_to_xml() as `python -I evtx_worker.py <file>` with a time limit, so a damaged or
booby-trapped file can at worst be stopped. Output (stdout): <Events>...</Events> with up to MAX_RECORDS events, then a
last line "<!-- read N records; stopped: reason -->". Nothing in the file is ever run.
"""
import sys
import time

MAX_RECORDS = 100_000
MAX_SECONDS = 90


def main():
    import Evtx.Evtx as evtx
    out = sys.stdout
    n, reason, t0 = 0, "", time.monotonic()
    out.write("<Events>\n")
    try:
        with evtx.Evtx(sys.argv[1]) as log:
            for rec in log.records():
                try:
                    out.write(rec.xml())
                    out.write("\n")
                except Exception:                      # noqa: BLE001 - one damaged record is skipped
                    continue
                n += 1
                if n >= MAX_RECORDS:
                    reason = f"only the first {MAX_RECORDS:,} events were read"
                    break
                if time.monotonic() - t0 > MAX_SECONDS:
                    reason = f"reading was stopped after {MAX_SECONDS} s"
                    break
    except Exception as exc:                           # noqa: BLE001 - a damaged file: keep what was read
        reason = f"the file is damaged after {n:,} events ({type(exc).__name__})"
    out.write("</Events>\n")
    out.write(f"<!-- read {n} records; stopped: {reason} -->\n")
    out.flush()


if __name__ == "__main__":
    main()
