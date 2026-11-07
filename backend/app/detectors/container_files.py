"""
Files hidden inside other files - read in memory, never unpacked to disk, never run (added 30 Oct).

  * disk images (.iso / .img): the ISO 9660 file system (with Joliet long names) - attackers mail ISO files because
    Windows opens them with a double-click and the files inside skip the "downloaded from the internet" warning
    (MITRE T1553.005)
  * OneNote notebooks (.one): files embedded in the page ("double-click to view") - a common 2023-2024 malware trick
  * tar / tar.gz / .tgz archives, and the original file name stored in a .gz file

Every reader has hard limits (number of files, bytes read, folder depth) and gives up quietly on a broken or hostile
file: it then returns what it could read, and the caller reports that the contents could not be checked.
"""
from __future__ import annotations

import gzip
import io
import struct
import tarfile

SECTOR = 2048
MAX_FILES = 200
MAX_TOTAL = 60 * 1024 * 1024        # bytes of inner files read from one container
MAX_MEMBER = 15 * 1024 * 1024       # one inner file
MAX_DEPTH = 4

ONENOTE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")      # {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
ONENOTE_FILEDATA = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")   # {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}


def is_iso(data: bytes) -> bool:
    return len(data) >= 17 * SECTOR and data[16 * SECTOR + 1:16 * SECTOR + 6] == b"CD001"


def is_onenote(data: bytes) -> bool:
    return data[:16] == ONENOTE_MAGIC


def iso_files(data: bytes) -> list[tuple[str, bytes]]:
    """[(path, bytes)] of the files in an ISO 9660 image (Joliet names when present)."""
    if not is_iso(data):
        return []
    root, joliet = None, False
    for n in range(16, 64):                                  # volume descriptors
        off = n * SECTOR
        vd = data[off:off + SECTOR]
        if len(vd) < 190 or vd[1:6] != b"CD001" or vd[0] == 255:
            break
        if vd[0] == 1 and root is None:
            root = vd[156:190]
        elif vd[0] == 2 and vd[88:90] == b"%/" and vd[90:91] in (b"@", b"C", b"E"):     # Joliet: UTF-16 names
            root, joliet = vd[156:190], True
    if root is None:
        return []
    out, total, seen = [], 0, set()
    todo = [("", struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0], 0)]
    while todo and len(out) < MAX_FILES:
        prefix, lba, size, depth = todo.pop(0)
        if lba in seen or depth > MAX_DEPTH:
            continue
        seen.add(lba)
        d = data[lba * SECTOR:lba * SECTOR + min(size, 1024 * 1024)]
        i = 0
        while i < len(d) and len(out) < MAX_FILES:
            ln = d[i]
            if ln == 0:                                      # records never cross a sector: jump to the next one
                i = (i // SECTOR + 1) * SECTOR
                continue
            rec = d[i:i + ln]
            i += ln
            if len(rec) < 34:
                break
            ext_lba, ext_size, flags, nlen = (struct.unpack_from("<I", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0],
                                              rec[25], rec[32])
            raw = rec[33:33 + nlen]
            if raw in (b"\x00", b"\x01"):                    # "." and ".."
                continue
            name = (raw.decode("utf-16-be", "ignore") if joliet else raw.decode("latin-1")).split(";")[0].rstrip(".")
            path = f"{prefix}{name}"
            if flags & 0x02:
                todo.append((path + "/", ext_lba, ext_size, depth + 1))
                continue
            take = min(ext_size, MAX_MEMBER, max(0, MAX_TOTAL - total))
            blob = data[ext_lba * SECTOR:ext_lba * SECTOR + take]
            total += len(blob)
            out.append((path, blob))
    return out


def onenote_files(data: bytes) -> list[bytes]:
    """Files embedded in a OneNote notebook (FileDataStoreObject: GUID, 8-byte length, 12 bytes, then the file)."""
    if not is_onenote(data):
        return []
    out, start, total = [], 0, 0
    while len(out) < MAX_FILES:
        i = data.find(ONENOTE_FILEDATA, start)
        if i < 0 or i + 36 > len(data):
            break
        size = struct.unpack_from("<Q", data, i + 16)[0]
        take = min(size, MAX_MEMBER, max(0, MAX_TOTAL - total))
        blob = data[i + 36:i + 36 + take]
        if blob:
            out.append(blob)
            total += len(blob)
        start = i + 36 + max(len(blob), 1)
    return out


def tar_files(data: bytes) -> list[tuple[str, bytes]]:
    """[(path, bytes)] of a tar / tar.gz / tgz archive (regular files only, read in memory)."""
    out, total, members, declared = [], 0, 0, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            for m in t:
                members += 1
                declared += max(m.size, 0)
                # stop early on archive bombs: too many entries, or more unpacked data than is worth reading through
                if len(out) >= MAX_FILES or members > 5 * MAX_FILES or declared > 4 * MAX_TOTAL:
                    break
                if not m.isfile():
                    continue
                take = min(m.size, MAX_MEMBER, max(0, MAX_TOTAL - total))
                f = t.extractfile(m)
                blob = f.read(take) if f and take else b""
                total += len(blob)
                out.append((m.name, blob))
    except (tarfile.TarError, OSError, EOFError, ValueError):
        pass
    return out


def gzip_inner(data: bytes) -> tuple[str, bytes] | None:
    """(original file name, first bytes) of a plain .gz file - the name the sender gave the packed file."""
    if data[:2] != b"\x1f\x8b" or len(data) < 10:
        return None
    flags, name, i = data[3], "", 10
    try:
        if flags & 0x04:                                     # FEXTRA
            i += 2 + struct.unpack_from("<H", data, i)[0]
        if flags & 0x08:                                     # FNAME
            end = data.index(b"\x00", i)
            name = data[i:end].decode("latin-1")
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
            head = g.read(MAX_MEMBER)
    except (ValueError, OSError, EOFError, struct.error):
        return (name, b"") if name else None
    return name, head
