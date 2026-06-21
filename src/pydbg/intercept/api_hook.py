"""API interceptor — records and decodes API calls made by the target process."""

import csv
import json
import time
from dataclasses import dataclass, field


@dataclass
class APICall:
    """Single recorded API call with arguments, return value, and optional decode info."""

    timestamp: int
    tid: int
    module: str
    function: str
    args: list = field(default_factory=list)
    decoded_args: dict = field(default_factory=dict)
    return_value: int = 0
    decoded_return: str = ""
    call_stack: list = field(default_factory=list)

    def __eq__(self, other):
        if not isinstance(other, APICall):
            return NotImplemented
        return (
            self.timestamp == other.timestamp
            and self.tid == other.tid
            and self.module == other.module
            and self.function == other.function
            and self.args == other.args
            and self.decoded_args == other.decoded_args
            and self.return_value == other.return_value
            and self.decoded_return == other.decoded_return
            and self.call_stack == other.call_stack
        )

    def __hash__(self):
        return hash((
            self.timestamp,
            self.tid,
            self.module,
            self.function,
            tuple(self.args),
            frozenset(self.decoded_args.items()),
            self.return_value,
            self.decoded_return,
            tuple(self.call_stack),
        ))


class APIInterceptor:
    """Records API calls made by the debuggee, with optional argument decoding.

    This class works at the *analysis* level — it does not install hooks itself.
    Instead it provides a registry for hook callbacks (via :meth:`intercept`) and
    stores :class:`APICall` records that can be queried or exported.
    """

    def __init__(self, session):
        self._s = session
        self._hooks = {}          # (module, function) -> decoder_fn or None
        self._calls = []          # list[APICall]
        self._decoders = {}       # (module, function) -> decoder_fn
        self._original_addrs = {} # (module, function) -> original_address

    # ------------------------------------------------------------------
    # Decoder registration
    # ------------------------------------------------------------------

    def register_decoder(self, module, function, decoder_fn):
        """Register a decoder function for *module*!*function*.

        *decoder_fn* receives ``(args: list) -> dict`` and returns a dict of
        decoded argument names/values.
        """
        self._decoders[(module.lower(), function.lower())] = decoder_fn

    # ------------------------------------------------------------------
    # Hook registration
    # ------------------------------------------------------------------

    def intercept(self, module, function, decoder=None):
        """Mark *module*!*function* for interception.

        If *decoder* is provided it is registered as the decoder for this
        function pair.  Returns ``True`` if the pair was newly registered,
        ``False`` if it was already present.
        """
        key = (module.lower(), function.lower())
        if key in self._hooks:
            return False
        self._hooks[key] = decoder
        if decoder is not None:
            self._decoders[key] = decoder
        return True

    def intercept_module(self, module, preset=None):
        """Intercept all functions in *module* using an optional *preset*.

        *preset* is a dict mapping function names to decoder functions.
        This base implementation simply stores the preset entries; subclasses
        or callers can expand the list by calling :meth:`intercept` for each
        known export.
        """
        if preset is None:
            preset = {}
        for func_name, decoder in preset.items():
            self.intercept(module, func_name, decoder=decoder)

    def intercept_com_vtable(self, obj_addr, interface_name, vtable_map):
        """Register interception for a COM vtable.

        *vtable_map* is a dict mapping vtable slot index to ``(func_name, decoder_fn)``
        for the given *interface_name*.  This stores each entry via
        :meth:`intercept` using the interface name as the module.
        """
        for _slot, (func_name, decoder) in vtable_map.items():
            self.intercept(interface_name, func_name, decoder=decoder)
        self._original_addrs[interface_name] = obj_addr

    # ------------------------------------------------------------------
    # Recording (called by hook callbacks)
    # ------------------------------------------------------------------

    def record_call(self, call: APICall):
        """Manually record an :class:`APICall`.  Intended for use by hook callbacks."""
        # Apply decoder if one is registered
        key = (call.module.lower(), call.function.lower())
        if key in self._decoders and not call.decoded_args:
            try:
                call.decoded_args = self._decoders[key](call.args)
            except Exception:
                pass
        self._calls.append(call)

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def get_calls(self, module=None, function=None, tid=None):
        """Return recorded calls, optionally filtered by *module*, *function*, *tid*."""
        result = self._calls
        if module is not None:
            result = [c for c in result if c.module.lower() == module.lower()]
        if function is not None:
            result = [c for c in result if c.function.lower() == function.lower()]
        if tid is not None:
            result = [c for c in result if c.tid == tid]
        return result

    def get_call_count(self):
        """Return a dict mapping ``module!function`` to call count."""
        counts = {}
        for c in self._calls:
            key = f"{c.module}!{c.function}"
            counts[key] = counts.get(key, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self, path):
        """Export all recorded calls to a JSON file at *path*."""
        data = []
        for c in self._calls:
            data.append({
                "timestamp": c.timestamp,
                "tid": c.tid,
                "module": c.module,
                "function": c.function,
                "args": c.args,
                "decoded_args": c.decoded_args,
                "return_value": c.return_value,
                "decoded_return": c.decoded_return,
                "call_stack": c.call_stack,
            })
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    def export_csv(self, path):
        """Export all recorded calls to a CSV file at *path*."""
        fieldnames = [
            "timestamp", "tid", "module", "function",
            "args", "decoded_args", "return_value", "decoded_return",
            "call_stack",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for c in self._calls:
                writer.writerow({
                    "timestamp": c.timestamp,
                    "tid": c.tid,
                    "module": c.module,
                    "function": c.function,
                    "args": json.dumps(c.args),
                    "decoded_args": json.dumps(c.decoded_args),
                    "return_value": c.return_value,
                    "decoded_return": c.decoded_return,
                    "call_stack": json.dumps(c.call_stack),
                })

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def clear(self):
        """Clear all recorded calls."""
        self._calls.clear()
