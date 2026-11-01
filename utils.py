import os
from typing import Generator

CONTENT_EXTS = (".zmulti", ".zpreset", ".zconfig")   # .zconfig covers *.patches.zconfig / *.presets.zconfig

def iter_content_files(root) -> Generator[str, None, None]:
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith(CONTENT_EXTS):
                yield os.path.join(dirpath, name)


def get_machine_key() -> bytes:
    """Return the 64-byte Blowfish key for this machine, as a bytes object."""
    if not os.path.exists("machine-key.key"):
        raise RuntimeError("machine-key.key file not found; run `./build_and_capture.sh` to capture this machine's key first")
    with open("machine-key.key", "rb") as f:
        key = f.read()
    key = parse_key(key.decode("utf-8"))
    if len(key) != 64:
        raise RuntimeError(f"machine-key.key file is {len(key)} bytes, expected 64")
    return key

def parse_key(s: str) -> bytes:
    """Accept a hex string (with optional spaces/0x) and return raw key bytes."""
    s = s.strip().lower().replace("0x", "").replace(" ", "").replace(":", "")
    return bytes.fromhex(s)

def looks_like_json(data: bytes) -> bool:
    """Return True if the given bytes look like JSON (starts with { or [)."""
    head = data.lstrip()[:1]
    return head in (b"{", b"[")

def write_bytes_to_file(path: str, data: bytes):
    """Write the given bytes to the given file path, creating parent directories if needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)