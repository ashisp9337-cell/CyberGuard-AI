"""(11 Nov) Import known contacts from a phone / Google / Outlook export, for the Friend / Relative / Known Contact
impersonation check (Settings -> Known Contacts -> Import).

Reads a vCard (.vcf - Android "Export contacts", iPhone / iCloud, Google "vCard") or a CSV (Google Contacts, Outlook)
and returns NAME + first E-MAIL only. Phone numbers, addresses, photos, birthdays and notes are never read into the
result, never stored and never logged. The file itself is read in memory and not written to disk.
"""
from __future__ import annotations

import csv
import io
import quopri
import re

MAX_BYTES = 2 * 1024 * 1024
MAX_CONTACTS = 2000
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ImportError_(ValueError):
    """The file cannot be imported; the message is safe to show."""


def _text(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _clean_name(s: str) -> str:
    return re.sub(r"\s+", " ", _CONTROL.sub(" ", s or "")).strip()[:200]


def _clean_email(s: str) -> str:
    s = (s or "").strip().strip("<>").lower()
    return s if EMAIL_RE.match(s) else ""


def _vcard_value(params: list[str], value: str) -> str:
    p = ";".join(params).upper()
    if "QUOTED-PRINTABLE" in p:
        m = re.search(r"CHARSET=([\w\-]+)", p)
        try:
            value = quopri.decodestring(value.encode("latin-1", "replace")).decode(m.group(1) if m else "utf-8", "replace")
        except (LookupError, ValueError):
            pass
    return re.sub(r"\\([,;\\])", r"\1", value.replace("\\n", " ").replace("\\N", " "))


def parse_vcard(text: str) -> list[dict]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"=\n(?=\S)", "", text)             # quoted-printable soft line break (vCard 2.1)
    text = re.sub(r"\n[ \t]", "", text)               # folded line (vCard 3.0 / 4.0)
    out, card = [], None
    for line in text.split("\n"):
        line = line.strip()
        up = line.upper()
        if up == "BEGIN:VCARD":
            card = {"fn": "", "n": "", "email": ""}
        elif up == "END:VCARD":
            if card is not None:
                out.append({"name": _clean_name(card["fn"] or card["n"]), "email": card["email"]})
            card = None
            if len(out) >= MAX_CONTACTS:
                break
        elif card is not None and ":" in line:
            left, value = line.split(":", 1)
            parts = left.split(";")
            prop = parts[0].split(".")[-1].upper()     # "item1.EMAIL" -> EMAIL
            if prop == "FN" and not card["fn"]:
                card["fn"] = _vcard_value(parts[1:], value)
            elif prop == "N" and not card["n"]:
                family, given, *rest = (_vcard_value(parts[1:], value).split(";") + ["", ""])[:5]
                card["n"] = " ".join(x for x in (given, rest[0] if rest else "", family) if x.strip())
            elif prop == "EMAIL" and not card["email"]:
                card["email"] = _clean_email(_vcard_value(parts[1:], value))
    return out


NAME_COLS = ("name", "display name", "full name")
FIRST_COLS, MIDDLE_COLS, LAST_COLS = ("first name", "given name"), ("middle name", "additional name"), ("last name", "family name")


def parse_csv(text: str) -> list[dict]:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = csv.reader(io.StringIO(text), dialect)
    try:
        header = [h.strip().lower() for h in next(rows)]
    except StopIteration:
        return []
    idx = {h: i for i, h in reversed(list(enumerate(header)))}
    name_i = next((idx[c] for c in NAME_COLS if c in idx), None)
    part_i = [next((idx[c] for c in cols if c in idx), None) for cols in (FIRST_COLS, MIDDLE_COLS, LAST_COLS)]
    email_i = [i for i, h in enumerate(header) if ("e-mail" in h or "email" in h) and "type" not in h and "label" not in h]
    if name_i is None and part_i[0] is None and part_i[2] is None:
        raise ImportError_("This CSV has no name column (expected 'Name' or 'First Name' / 'Last Name'). Export the "
                           "contacts again as 'Google CSV', 'Outlook CSV' or 'vCard'.")
    out = []
    for row in rows:
        get = lambda i: row[i].strip() if i is not None and i < len(row) else ""   # noqa: E731
        name = get(name_i) or " ".join(x for x in (get(i) for i in part_i) if x)
        email = next((e for e in (_clean_email(get(i)) for i in email_i) if e), "")
        if name or email:
            out.append({"name": _clean_name(name), "email": email})
        if len(out) >= MAX_CONTACTS:
            break
    return out


def parse(raw: bytes) -> tuple[str, list[dict], int]:
    """-> (format, contacts [{"name", "email"}] with a name, unique in this file, number skipped for having no name)."""
    if len(raw) > MAX_BYTES:
        raise ImportError_("The file is larger than 2 MB. Export fewer contacts, or without photos.")
    if b"\x00" in raw[:2000] and raw[:2] not in (b"\xff\xfe", b"\xfe\xff"):
        raise ImportError_("This is not a contacts file. Choose a .vcf (vCard) or .csv export.")
    text = _text(raw)
    if "BEGIN:VCARD" in text.upper():
        kind, found = "vCard", parse_vcard(text)
    else:
        kind, found = "CSV", parse_csv(text)
    seen, out, no_name = set(), [], 0
    for c in found:
        if not c["name"]:
            no_name += 1
            continue
        key = (c["name"].lower(), c["email"])
        if key not in seen:
            seen.add(key)
            out.append(c)
    if not out and not no_name:
        raise ImportError_("No contacts were found in this file. Choose a .vcf (vCard) or .csv contacts export.")
    return kind, out, no_name
