#!/usr/bin/env python3
# capture_key.py  — lldb driver that extracts the LABS Blowfish key.
# -----------------------------------------------------------------------------
# Run INSIDE lldb, e.g.:
#   lldb --batch \
#        -o "command script import tools/capture_key.py" \
#        -o "capture_run tools/labs_host" \
#        2>&1
#
# What it does:
#   1. Creates a target for our little host (tools/labs_host) and launches it.
#   2. Stops at the host's `capture_ready` marker — at which point the LABS
#      Mach-O image is mapped into the process.
#   3. Resolves the Blowfish constructor (file offset 0xf37640 inside the LABS
#      image, x86_64 slice of 3.7.29) to its runtime address and sets a
#      breakpoint there. At that constructor, by the SysV calling convention:
#         rdi = this (the BlowFish object)
#         rsi = keyData   (pointer to the raw key bytes)
#         edx = keyBytes  (key length)
#   4. Each time the breakpoint hits, it dumps the key bytes (hex + ascii) and
#      auto-continues, collecting every distinct key the plugin builds.
#   5. Prints a summary. The 17-byte ASCII "typhon_presets001" is the fixed
#      user-preset key; the long (~72-byte) binary one is the per-machine
#      content/license key we actually need.
# -----------------------------------------------------------------------------
import lldb

# Blowfish ctor offset within the LABS 3.7.29 x86_64 slice (__TEXT vmaddr = 0,
# so this file-offset adds directly to the image load address).
CTOR_OFFSET = 0xF37640

_seen = []  # list of (length, bytes)


def _on_ctor(frame, bp_loc, internal_dict):
    """Breakpoint callback at BlowFish(this, keyData=rsi, keyBytes=edx)."""
    rsi = frame.FindRegister("rsi").GetValueAsUnsigned()
    rdx = frame.FindRegister("rdx").GetValueAsUnsigned()
    length = rdx & 0xFFFFFFFF
    proc = frame.GetThread().GetProcess()
    err = lldb.SBError()
    n = min(length, 256) if length else 0
    data = proc.ReadMemory(rsi, n, err) if n else b""
    if err.Success():
        try:
            asc = bytes(data).decode("latin1")
        except Exception:
            asc = ""
        # Record the caller so distinct construction sites are visible.
        thread = frame.GetThread()
        caller = thread.GetFrameAtIndex(1) if thread.GetNumFrames() > 1 else None
        if caller:
            ret = caller.GetPCAddress().GetLoadAddress(frame.GetThread().GetProcess().GetTarget())
            mod = caller.GetModule().GetFileSpec().GetFilename() or "?"
            site = f" from={mod}!{ret:#x}"
        else:
            site = ""
        print(f"[KEY] len={length} ptr={rsi:#x}{site}\n      hex   = {bytes(data).hex()}\n      ascii = {asc!r}")
        _seen.append((length, bytes(data)))
    else:
        print(f"[KEY] len={length} ptr={rsi:#x} <read failed: {err.GetCString()}>")
    return False  # return False == do not stop; continue automatically


def capture_run(debugger, command, result, internal_dict):
    # command: "<host_path> [ctor_offset_hex]"
    parts = command.split()
    host = parts[0]
    global CTOR_OFFSET
    if len(parts) > 1:
        CTOR_OFFSET = int(parts[1], 16)
    debugger.SetAsync(False)
    target = debugger.CreateTarget(host)
    if not target:
        print("!! could not create target for", host); return

    # Stop once the plugin image is mapped (host calls capture_ready() right
    # after dlopen'ing LABS).
    target.BreakpointCreateByName("capture_ready")
    target.BreakpointCreateByName("capture_done")

    proc = target.LaunchSimple(None, None, None)
    if not proc:
        print("!! launch failed"); return

    # We should now be stopped at capture_ready. Find the LABS module and arm
    # the constructor breakpoint at its runtime address.
    labs = None
    for m in target.module_iter():
        name = m.GetFileSpec().GetFilename() or ""
        if name == "LABS":
            labs = m; break
    if not labs:
        print("!! LABS module not found; images:",
              [m.GetFileSpec().GetFilename() for m in target.module_iter()])
        return

    file_addr = lldb.SBAddress(CTOR_OFFSET, target)   # file offset within image
    # Resolve to a section-based address inside the LABS module:
    ctor = labs.ResolveFileAddress(CTOR_OFFSET)
    bp = target.BreakpointCreateBySBAddress(ctor)
    bp.SetScriptCallbackFunction("capture_key._on_ctor")
    load = ctor.GetLoadAddress(target)
    print(f"[drv] LABS base resolved; Blowfish ctor @ {load:#x} (offset {CTOR_OFFSET:#x})")

    # Run until the process exits (callbacks fire along the way).
    proc.Continue()

    print("\n==================== CAPTURE SUMMARY ====================")
    # The Blowfish ctor fires once per construction (hundreds-to-thousands of
    # times during load). The per-machine content key dominates overwhelmingly;
    # stray one-off constructions (teardown, scratch buffers) show up a handful
    # of times at most. Rank by frequency and treat the most-common key as THE
    # machine key rather than writing every distinct value we happened to see.
    from collections import Counter

    counts = Counter(_seen)  # (length, bytes) -> occurrences
    if not counts:
        print("  err=(no Blowfish ctor calls observed)")
        print("========================================================")
        return

    ranked = counts.most_common()
    print(f"  {len(ranked)} distinct Blowfish key(s) captured "
          f"({sum(counts.values())} total ctor hits):")

    written = 0
    for (ln, b), n in ranked:
        kind = "fixed preset key" if b.startswith(b"typhon") else (
               "per-machine key" if ln >= 24 else "?")
        hex_bytes = b.hex()
        # Only the dominant value is the real key; log the rest but skip them.
        is_machine_key = written == 0 and kind == "per-machine key"
        tag = "WRITE" if is_machine_key else "skip "
        print(f"  [{tag}] seen={n:<5} len={ln:<4} {kind}    hex={hex_bytes}")
        if is_machine_key:
            filename = "machine-key.key"
            with open(filename, "wb") as f:
                f.write(hex_bytes.encode("utf-8"))
            print(f"  success={filename} written ({len(hex_bytes)//2} bytes)")
            written += 1

    if not written:
        print("  err=(no per-machine key among captured constructions)")

    print("========================================================")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f capture_key.capture_run capture_run")
