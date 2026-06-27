#!/usr/bin/env python3
"""Capture decoded sprite data from OdenTodo.exe at runtime.

The RCDATA archive stores encoded/compressed sprite data. This script
launches the game under the pydbg debugger, reads the DIB section
(rendered pixels) and palette directly from game memory, then saves
captures at multiple game states.

Memory layout (from static analysis):
    0x40EB7C  DIB section pixel pointer (4 bytes, set by CreateDIBSection)
    0x40EB88  Palette handle (4 bytes, HPALETTE)
    0x40EB94  Palette entries (1024 bytes, PALETTEENTRY[256]: R,G,B,Flags)

Game runs at 640x480, 8bpp indexed color.
"""

import struct
import time
import os
import sys

# Ensure pydbg is importable from this worktree
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from pydbg import Debugger, _pydbg
from pydbg.stealth import AntiAware


# Game memory addresses (verified by static analysis)
DIB_PTR_ADDR = 0x40EB7C      # Pointer to DIB section pixel buffer
PALETTE_HANDLE_ADDR = 0x40EB88  # HPALETTE
PALETTE_ENTRIES_ADDR = 0x40EB94  # PALETTEENTRY[256] (1024 bytes)

# Display parameters
SCREEN_W = 640
SCREEN_H = 480
DIB_SIZE = SCREEN_W * SCREEN_H  # 307,200 bytes

# Output directory
OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'Output', 'odentodo', 'captures'
)

GAME_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'Output', 'odentodo', 'OdenTodo.exe'
)


def save_bmp(path, pixels, palette_rgb, w, h):
    """Save 8bpp indexed pixels as a BMP file.

    Args:
        path: Output file path.
        pixels: bytes-like of length w*h, each byte is a palette index.
        palette_rgb: bytes-like of length 768 (256 * 3 RGB).
        w: Image width in pixels.
        h: Image height in pixels.
    """
    row_size = (w + 3) & ~3  # BMP rows are 4-byte aligned
    pixel_data_size = row_size * h
    file_size = 14 + 40 + 1024 + pixel_data_size

    # BITMAPFILEHEADER (14 bytes)
    file_header = struct.pack('<2sIHHI', b'BM', file_size, 0, 0, 14 + 40 + 1024)

    # BITMAPINFOHEADER (40 bytes) -- positive height = bottom-up
    info_header = struct.pack(
        '<IiiHHIIiiII',
        40,           # biSize
        w,            # biWidth
        h,            # biHeight (positive = bottom-up)
        1,            # biPlanes
        8,            # biBitCount
        0,            # biCompression (BI_RGB)
        pixel_data_size,  # biSizeImage
        2835,         # biXPelsPerMeter
        2835,         # biYPelsPerMeter
        0,            # biClrUsed
        0,            # biClrImportant
    )

    # Color table: 256 entries in BGRA format
    color_table = bytearray(1024)
    for i in range(256):
        if i * 3 + 2 < len(palette_rgb):
            r = palette_rgb[i * 3]
            g = palette_rgb[i * 3 + 1]
            b = palette_rgb[i * 3 + 2]
            color_table[i * 4:i * 4 + 4] = bytes([b, g, r, 0])

    # Pixel data (bottom-up, padded to 4-byte boundary)
    pixel_rows = bytearray(pixel_data_size)
    for row in range(h):
        src = row * w
        dst = row * row_size
        copy_len = min(w, len(pixels) - src)
        if copy_len > 0:
            pixel_rows[dst:dst + copy_len] = pixels[src:src + copy_len]

    with open(path, 'wb') as f:
        f.write(file_header + info_header + bytes(color_table) + bytes(pixel_rows))


def read_palette(dbg):
    """Read the game's palette from memory and convert to RGB.

    Returns:
        bytearray of 768 bytes (256 * 3 RGB).
    """
    palette_data = dbg.read_memory(PALETTE_ENTRIES_ADDR, 1024)

    palette_rgb = bytearray(768)
    for i in range(256):
        # PALETTEENTRY format: peRed, peGreen, peBlue, peFlags
        r, g, b, _flags = palette_data[i * 4:i * 4 + 4]
        palette_rgb[i * 3] = r
        palette_rgb[i * 3 + 1] = g
        palette_rgb[i * 3 + 2] = b

    return palette_rgb


def find_game_window(pid):
    """Find the window handle belonging to the game process."""
    import ctypes
    import ctypes.wintypes as wintypes

    user32 = ctypes.windll.user32
    game_hwnd = None

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def enum_cb(hwnd, _lparam):
        nonlocal game_hwnd
        proc_id = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(proc_id))
        if proc_id.value == pid:
            if user32.IsWindowVisible(hwnd):
                game_hwnd = hwnd
                return False
        return True

    user32.EnumWindows(enum_cb, 0)
    return game_hwnd


def send_key(hwnd, vk_code, delay=0.05):
    """Send a key press/release to the game window."""
    import ctypes

    user32 = ctypes.windll.user32
    WM_KEYDOWN = 0x0100
    WM_KEYUP = 0x0101

    scan_code = user32.MapVirtualKeyA(vk_code, 0)
    lparam_down = (1 & 0xFFFF) | ((scan_code & 0xFF) << 16)
    user32.PostMessageA(hwnd, WM_KEYDOWN, vk_code, lparam_down)
    time.sleep(delay)
    lparam_up = lparam_down | (1 << 30) | (1 << 31)
    user32.PostMessageA(hwnd, WM_KEYUP, vk_code, lparam_up)


def drain_events(dbg, timeout_ms=200, max_events=60):
    """Consume pending debug events."""
    for _ in range(max_events):
        event = dbg.wait_event(timeout_ms=timeout_ms)
        if event is None:
            break
        dbg.continue_event(event.pid, event.tid)
        if event.type == 'EXIT_PROCESS':
            return False
    return True


def analyze_pixels(pixels, label=""):
    """Analyze pixel data quality and return stats."""
    unique = len(set(pixels))
    non_zero = sum(1 for p in pixels if p != 0)

    # Detect background-heavy frames
    from collections import Counter
    top = Counter(pixels).most_common(5)
    top_str = ', '.join(f'{v}:{c}' for v, c in top)

    return {
        'label': label,
        'unique_colors': unique,
        'non_zero_pixels': non_zero,
        'total_pixels': len(pixels),
        'top_colors': top_str,
    }


def capture_dib(dbg, label, palette_rgb):
    """Read DIB section pixels and save as BMP.

    Args:
        dbg: Debugger instance.
        label: Descriptive name for this capture.
        palette_rgb: 768-byte RGB palette.

    Returns:
        Path to saved BMP, or None on failure.
    """
    # Read the DIB section pointer
    raw = dbg.read_memory(DIB_PTR_ADDR, 4)
    dib_ptr = struct.unpack('<I', raw)[0]

    if dib_ptr == 0:
        print(f"  [{label}] DIB pointer is NULL -- game not rendering yet")
        return None

    # Read pixels
    try:
        pixels = dbg.read_memory(dib_ptr, DIB_SIZE)
    except Exception as e:
        print(f"  [{label}] Failed to read DIB at 0x{dib_ptr:X}: {e}")
        return None

    # Analyze
    stats = analyze_pixels(pixels, label)
    print(f"  [{label}] DIB ptr=0x{dib_ptr:X}  "
          f"unique={stats['unique_colors']:3d}  "
          f"non_zero={stats['non_zero_pixels']:6d}/{stats['total_pixels']}  "
          f"top=[{stats['top_colors']}]")

    # Save
    filename = f"dib_{label}.bmp"
    path = os.path.join(OUTPUT_DIR, filename)
    save_bmp(path, pixels, palette_rgb, SCREEN_W, SCREEN_H)
    print(f"  [{label}] Saved: {filename} ({SCREEN_W}x{SCREEN_H})")

    return path


def search_decompressed_archive(dbg, dib_ptr):
    """Search game memory for decompressed sprite archive data.

    The RCDATA archive is 585,221 bytes. If the game decompresses it
    into a heap buffer before rendering, we can find it by looking for
    the known palette signature (first 12 bytes all zero).

    Returns:
        Tuple of (archive_address, archive_size) or (None, None).
    """
    # Read the RCDATA raw archive to get the first 32 bytes as a search pattern
    rcdata_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '..', 'Output', 'odentodo', 'assets', 'rcdata_raw.bin'
    )

    if not os.path.exists(rcdata_path):
        return None, None

    with open(rcdata_path, 'rb') as f:
        rcdata = f.read(585221)

    # Use a distinctive pattern from the archive (bytes 0x300-0x30F = dir header)
    pattern = rcdata[0x300:0x310]
    print(f"\n  Searching for decompressed archive (pattern: {pattern.hex()})...")

    # Search in a wide range around the DIB pointer
    search_start = max(0, dib_ptr - 0x200000)
    search_end = dib_ptr + 0x200000
    search_size = search_end - search_start

    chunk = 0x10000  # 64KB chunks
    for offset in range(0, search_size, chunk):
        addr = search_start + offset
        read_size = min(chunk + 16, search_size - offset)
        try:
            data = dbg.read_memory(addr, read_size)
            idx = data.find(pattern)
            if idx >= 0:
                found_addr = addr + idx
                # Verify: read 16 more bytes and check against archive
                verify = dbg.read_memory(found_addr, 16)
                if verify == pattern:
                    # Full verification: check if the archive matches at this offset
                    try:
                        full_check = dbg.read_memory(found_addr + 0x300, 16)
                        if full_check == rcdata[0x300:0x310]:
                            # Check palette too
                            pal_check = dbg.read_memory(found_addr, 48)
                            if pal_check == rcdata[:48]:
                                print(f"  Found archive at 0x{found_addr:X} "
                                      f"(palette+header match)")
                                return found_addr, 585221
                    except Exception:
                        continue
        except Exception:
            continue

    print("  Decompressed archive not found in memory scan")
    return None, None


def search_palette_buffer(dbg):
    """Search for the palette buffer that the game uses at runtime.

    The game creates a LOGPALETTE/PALETTE and stores entries at 0x40EB94.
    We can also search for the actual palette used in the DIB color table.
    """
    # Read the known palette
    palette_data = dbg.read_memory(PALETTE_ENTRIES_ADDR, 1024)

    # Search for a copy of this palette in heap memory
    # Use first 16 bytes of the palette as pattern
    pattern = palette_data[:16]

    print(f"\n  Searching for palette copies in memory...")
    print(f"  Pattern: {pattern.hex()}")

    # Search around the data section
    search_ranges = [
        (0x400000, 0x400000 + 0x300000),  # .data section area
        (0x10000, 0x800000),               # Low memory
    ]

    found = []
    for start, end in search_ranges:
        for offset in range(start, end, 0x10000):
            try:
                data = dbg.read_memory(offset, 0x10000 + 16)
                idx = 0
                while True:
                    idx = data.find(pattern, idx)
                    if idx < 0:
                        break
                    addr = offset + idx
                    # Verify it's a full palette (check 48 bytes)
                    verify = dbg.read_memory(addr, 48)
                    if verify == palette_data[:48]:
                        found.append(addr)
                    idx += 1
            except Exception:
                continue

    for addr in found:
        print(f"  Palette copy at 0x{addr:X}")

    return found


def main():
    print("=" * 60)
    print("OdenTodo Sprite Capture -- DIB Section Reader")
    print("=" * 60)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Kill any existing instance
    os.system('taskkill /F /IM OdenTodo.exe >nul 2>&1')
    time.sleep(1)

    # Launch game
    dbg = Debugger()

    print("\n[1] Launching OdenTodo.exe...")
    try:
        pid, tid = dbg.create_process(GAME_PATH)
        print(f"    PID={pid}, TID={tid}")
    except Exception as e:
        print(f"    Failed to launch: {e}")
        return 1

    # Wait for initial debug events
    print("    Waiting for game initialization...")
    drain_events(dbg, timeout_ms=500, max_events=100)
    time.sleep(2)

    # Apply anti-debug patches
    print("\n[2] Applying anti-debug patches...")
    anti = AntiAware(dbg._session)
    try:
        anti.hide_all()
        print("    PEB/heap flags patched")
    except Exception as e:
        print(f"    Anti-debug warning: {e}")

    # Wait for game to fully initialize
    print("    Waiting for game window...")
    time.sleep(3)

    # Drain any more events
    drain_events(dbg, timeout_ms=200, max_events=50)

    # Find game window
    print("\n[3] Finding game window...")
    hwnd = find_game_window(pid)
    if hwnd:
        print(f"    Window handle: 0x{hwnd:X}")
    else:
        print("    WARNING: No window found -- trying Class name...")
        import ctypes
        hwnd = ctypes.windll.user32.FindWindowA(b"OdenTodoFish", None)
        if hwnd:
            print(f"    Found by class: 0x{hwnd:X}")
        else:
            print("    WARNING: Could not find game window")

    # Read palette
    print("\n[4] Reading palette from game memory...")
    try:
        palette_rgb = read_palette(dbg)
        non_zero = sum(1 for b in palette_rgb if b != 0)
        print(f"    Palette: {non_zero}/768 non-zero bytes")
        print(f"    First 5 entries:")
        for i in range(5):
            r = palette_rgb[i * 3]
            g = palette_rgb[i * 3 + 1]
            b = palette_rgb[i * 3 + 2]
            print(f"      [{i:3d}] R={r:3d} G={g:3d} B={b:3d}")
    except Exception as e:
        print(f"    Failed to read palette: {e}")
        palette_rgb = bytearray(768)

    # Read DIB pointer
    print("\n[5] Reading DIB section pointer...")
    try:
        raw = dbg.read_memory(DIB_PTR_ADDR, 4)
        dib_ptr = struct.unpack('<I', raw)[0]
        print(f"    DIB pointer: 0x{dib_ptr:X}")

        if dib_ptr == 0:
            print("    DIB section not initialized yet, waiting longer...")
            time.sleep(5)
            raw = dbg.read_memory(DIB_PTR_ADDR, 4)
            dib_ptr = struct.unpack('<I', raw)[0]
            print(f"    DIB pointer (retry): 0x{dib_ptr:X}")
    except Exception as e:
        print(f"    Failed to read DIB pointer: {e}")
        dib_ptr = 0

    # Search for decompressed archive in memory
    print("\n[6] Searching for decompressed archive data...")
    archive_addr, archive_size = search_decompressed_archive(dbg, dib_ptr)

    # Search for palette copies
    print("\n[7] Searching for palette copies...")
    palette_copies = search_palette_buffer(dbg)

    # Capture initial state
    print("\n[8] Capturing game states...")
    captures = []

    # State 1: Initial (title screen)
    print("\n  --- State: initial (title screen) ---")
    path = capture_dib(dbg, 'initial', palette_rgb)
    if path:
        captures.append(('initial', path))

    # Send input to advance the game through different states
    input_states = [
        ('after_enter',    [0x0D],              "Press ENTER"),
        ('menu_nav_up',    [0x26],              "Press UP arrow"),
        ('menu_nav_down',  [0x28],              "Press DOWN arrow"),
        ('menu_nav_left',  [0x25],              "Press LEFT arrow"),
        ('menu_nav_right', [0x27],              "Press RIGHT arrow"),
        ('after_space',    [0x20],              "Press SPACE"),
        ('after_escape',   [0x1B],              "Press ESC"),
    ]

    for state_name, keys, description in input_states:
        print(f"\n  --- State: {state_name} ({description}) ---")

        if hwnd:
            for vk in keys:
                send_key(hwnd, vk, delay=0.05)
                time.sleep(0.3)

            # Wait for game to respond and render
            time.sleep(0.5)
            drain_events(dbg, timeout_ms=100, max_events=20)

        path = capture_dib(dbg, state_name, palette_rgb)
        if path:
            captures.append((state_name, path))

    # Capture with longer pauses between complex sequences
    print("\n  --- State: after_multi_input ---")
    if hwnd:
        # Simulate gameplay: ENTER -> navigate -> SPACE -> navigate
        for vk in [0x0D, 0x26, 0x26, 0x20, 0x28, 0x28, 0x0D]:
            send_key(hwnd, vk, delay=0.05)
            time.sleep(0.4)
        time.sleep(1)
        drain_events(dbg, timeout_ms=100, max_events=20)

    path = capture_dib(dbg, 'multi_input', palette_rgb)
    if path:
        captures.append(('multi_input', path))

    # Capture with ESC to go back to title
    print("\n  --- State: back_to_title ---")
    if hwnd:
        for _ in range(3):
            send_key(hwnd, 0x1B, delay=0.05)
            time.sleep(0.5)
        time.sleep(1)
        drain_events(dbg, timeout_ms=100, max_events=20)

    path = capture_dib(dbg, 'back_to_title', palette_rgb)
    if path:
        captures.append(('back_to_title', path))

    # Save palette as standalone BMP for reference
    print("\n[9] Saving palette reference...")
    palette_bmp_path = os.path.join(OUTPUT_DIR, 'palette_reference.bmp')
    # Create a 16x16 grid showing all 256 palette colors
    grid_w, grid_h = 16, 16
    grid_pixels = bytearray(grid_w * grid_h)
    for i in range(256):
        grid_pixels[i] = i
    save_bmp(palette_bmp_path, grid_pixels, palette_rgb, grid_w, grid_h)
    print(f"    Saved: palette_reference.bmp (16x16 grid)")

    # Summary
    print("\n" + "=" * 60)
    print("Capture Summary")
    print("=" * 60)
    print(f"\nDIB pointer:    0x{dib_ptr:X}")
    print(f"Palette:        {sum(1 for b in palette_rgb if b != 0)}/768 non-zero")
    print(f"Captures saved: {len(captures)}")
    for name, path in captures:
        size = os.path.getsize(path) if os.path.exists(path) else 0
        print(f"  {name:20s} -> {os.path.basename(path):30s} ({size:,} bytes)")
    if archive_addr:
        print(f"Archive found:  0x{archive_addr:X} ({archive_size:,} bytes)")
    if palette_copies:
        print(f"Palette copies: {len(palette_copies)} found")
    print(f"\nOutput directory: {OUTPUT_DIR}")

    # Cleanup
    print("\n[10] Cleaning up...")
    try:
        dbg.terminate_process(exit_code=0)
    except Exception:
        try:
            dbg.detach(pid)
        except Exception:
            pass

    print("\nDone.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
