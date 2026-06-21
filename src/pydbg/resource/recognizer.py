"""Resource data format recognizer.

Auto-identifies resource data formats by checking magic bytes (signatures)
and applying heuristic analysis for palettes and sprite dimensions.
"""

import struct


class ResourceRecognizer:
    """Identify resource data formats from raw bytes.

    Supports WAV, BMP, PNG, GIF by signature, and palette/sprite
    detection by heuristic.
    """

    SIGNATURES = {
        b'RIFF': 'wav',
        b'BM': 'bmp',
        b'\x89PNG': 'png',
        b'GIF8': 'gif',
    }

    def recognize(self, data):
        """Identify the format of raw resource data.

        Args:
            data: Raw bytes of the resource.

        Returns:
            dict with keys: format, width, height, bpp, extra.
            'format' is one of the known format strings or 'unknown'.
            'width', 'height', 'bpp' are None when not determinable.
            'extra' is a dict of format-specific metadata.
        """
        result = {
            'format': 'unknown',
            'width': None,
            'height': None,
            'bpp': None,
            'extra': {},
        }

        if not data:
            return result

        # Check signatures (longest match first to avoid prefix collisions)
        for sig in sorted(self.SIGNATURES, key=len, reverse=True):
            if data[:len(sig)] == sig:
                fmt = self.SIGNATURES[sig]
                result['format'] = fmt

                if fmt == 'bmp':
                    bmp_info = self._parse_bmp_header(data)
                    if bmp_info:
                        result['width'] = bmp_info['width']
                        result['height'] = bmp_info['height']
                        result['bpp'] = bmp_info['bpp']
                        result['extra'] = bmp_info

                return result

        # Try palette heuristic
        palette = self.recognize_palette(data)
        if palette is not None:
            result['format'] = 'palette'
            result['bpp'] = palette['bpp']
            result['extra'] = palette
            return result

        return result

    def recognize_palette(self, data):
        """Detect whether data looks like a color palette.

        A 256-entry RGB palette is exactly 768 bytes (256 * 3).
        A 256-entry RGBA palette is exactly 1024 bytes (256 * 4).

        Args:
            data: Raw bytes to analyze.

        Returns:
            dict with entries, bpp, bytes_per_entry if detected,
            or None if the data does not look like a palette.
        """
        size = len(data)
        if size == 768:
            return {
                'entries': 256,
                'bpp': 24,
                'bytes_per_entry': 3,
            }
        if size == 1024:
            return {
                'entries': 256,
                'bpp': 32,
                'bytes_per_entry': 4,
            }
        return None

    def recognize_sprite(self, data, width=None):
        """Guess possible sprite dimensions from raw pixel data.

        If width is provided, computes the matching height.
        Otherwise returns a list of (width, height) pairs whose
        product equals the data length.

        Args:
            data: Raw pixel bytes.
            width: Optional known width in pixels.

        Returns:
            If width is given: dict with 'width' and 'height'.
            Otherwise: list of (width, height) tuples.
        """
        size = len(data)
        if size == 0:
            return [] if width is None else {'width': 0, 'height': 0}

        if width is not None:
            if width <= 0:
                return {'width': 0, 'height': 0}
            height = size // width
            return {'width': width, 'height': height}

        # Find all factor pairs
        pairs = []
        for w in range(1, min(size, 4096) + 1):
            if size % w == 0:
                h = size // w
                if h <= 4096:
                    pairs.append((w, h))
        return pairs

    @staticmethod
    def _parse_bmp_header(data):
        """Extract width, height, and bpp from a BMP DIB header.

        Supports BITMAPINFOHEADER (40 bytes) and common variants.

        Args:
            data: Raw BMP file bytes starting with the 'BM' signature.

        Returns:
            dict with 'width', 'height', 'bpp', or None on failure.
        """
        if len(data) < 26:
            return None
        if data[:2] != b'BM':
            return None

        # BITMAPFILEHEADER: bfOffBits at offset 10 (not needed here)
        # DIB header starts at offset 14
        dib_size = struct.unpack_from('<I', data, 14)[0]
        if dib_size < 40:
            return None

        width = struct.unpack_from('<i', data, 18)[0]
        height = struct.unpack_from('<i', data, 22)[0]
        bpp = struct.unpack_from('<H', data, 28)[0]

        # height can be negative (top-down BMP)
        if width <= 0:
            return None

        return {
            'width': width,
            'height': abs(height),
            'bpp': bpp,
        }
