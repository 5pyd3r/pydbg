"""DirectSound API preset definitions."""

DSOUND_API_PRESET = {
    "DirectSoundCreate": {
        "dll": "dsound.dll",
        "params": [
            {"name": "pcGuidDevice", "type": "pointer"},
            {"name": "ppDS", "type": "pointer"},
            {"name": "pUnkOuter", "type": "pointer"},
        ],
        "ret_type": "hresult",
        "convention": "stdcall",
    },
    "DirectSoundCreate8": {
        "dll": "dsound.dll",
        "params": [
            {"name": "pcGuidDevice", "type": "pointer"},
            {"name": "ppDS8", "type": "pointer"},
            {"name": "pUnkOuter", "type": "pointer"},
        ],
        "ret_type": "hresult",
        "convention": "stdcall",
    },
}
