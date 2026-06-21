"""API presets for common DirectX and Win32 function interception."""

from .ddraw import DDRAW_API_PRESET, DDRAW_HRESULTS, DDRAW_VTABLE_METHODS, decode_hresult
from .dsound import DSOUND_API_PRESET
from .win32 import WIN32_API_PRESET

_PRESETS = {
    "ddraw": DDRAW_API_PRESET,
    "dsound": DSOUND_API_PRESET,
    "win32": WIN32_API_PRESET,
}


def load_preset(name: str) -> dict:
    """Load an API preset by name.

    Args:
        name: One of 'ddraw', 'dsound', 'win32'.

    Returns:
        The preset dictionary mapping API names to their definitions.

    Raises:
        ValueError: If the preset name is not recognized.
    """
    if name not in _PRESETS:
        raise ValueError(
            f"Unknown preset '{name}'. Available: {list(_PRESETS.keys())}"
        )
    return _PRESETS[name]


__all__ = [
    "DDRAW_API_PRESET",
    "DDRAW_VTABLE_METHODS",
    "DDRAW_HRESULTS",
    "DSOUND_API_PRESET",
    "WIN32_API_PRESET",
    "decode_hresult",
    "load_preset",
]
