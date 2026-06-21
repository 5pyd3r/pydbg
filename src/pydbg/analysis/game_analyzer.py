"""Game-specific analysis helpers for Win32 games."""


class GameAnalyzer:
    """Specialized analyzers for old Win32 games."""

    def __init__(self, workbench):
        """
        Args:
            workbench: AnalysisWorkbench instance.
        """
        self._wb = workbench

    def analyze_game_loop(self):
        """Analyze the game's main loop structure.

        Returns dict with:
        - messages: list of intercepted message dispatches
        - frame_times: list of frame delta times
        - loop_function: address of the main loop (if detected)
        """
        result = {'messages': [], 'frame_times': [], 'loop_function': None}

        if self._wb._interceptor is None:
            return result

        calls = self._wb._interceptor.get_calls()
        for call in calls:
            if call.function in ('PeekMessageA', 'PeekMessageW',
                                 'GetMessageA', 'GetMessageW',
                                 'DispatchMessageA', 'DispatchMessageW'):
                result['messages'].append({
                    'function': call.function,
                    'timestamp': call.timestamp,
                    'args': call.args,
                })

        return result

    def analyze_rendering_pipeline(self):
        """Analyze DirectDraw rendering calls.

        Returns dict with:
        - surfaces: list of surface operations
        - blts: list of Blt/BltFast calls
        - flips: list of Flip calls
        """
        result = {'surfaces': [], 'blts': [], 'flips': []}

        if self._wb._interceptor is None:
            return result

        calls = self._wb._interceptor.get_calls()
        for call in calls:
            if call.function == 'CreateSurface':
                result['surfaces'].append({
                    'timestamp': call.timestamp,
                    'args': call.args,
                    'return': call.decoded_return,
                })
            elif call.function in ('Blt', 'BltFast'):
                result['blts'].append({
                    'function': call.function,
                    'timestamp': call.timestamp,
                    'args': call.args,
                })
            elif call.function == 'Flip':
                result['flips'].append({
                    'timestamp': call.timestamp,
                    'args': call.args,
                })

        return result

    def analyze_audio_system(self):
        """Analyze DirectSound calls.

        Returns dict with:
        - buffers: list of sound buffer operations
        - plays: list of Play calls
        """
        result = {'buffers': [], 'plays': []}

        if self._wb._interceptor is None:
            return result

        calls = self._wb._interceptor.get_calls()
        for call in calls:
            if call.function == 'CreateSoundBuffer':
                result['buffers'].append({
                    'timestamp': call.timestamp,
                    'args': call.args,
                })
            elif call.function == 'Play':
                result['plays'].append({
                    'timestamp': call.timestamp,
                    'args': call.args,
                })

        return result

    def analyze_input_handling(self):
        """Analyze input message handling.

        Returns dict with:
        - key_map: mapping of virtual key codes to actions
        - messages: list of input-related messages
        """
        result = {'key_map': {}, 'messages': []}

        if self._wb._interceptor is None:
            return result

        calls = self._wb._interceptor.get_calls()
        for call in calls:
            if call.function in ('PeekMessageA', 'PeekMessageW',
                                 'GetMessageA', 'GetMessageW'):
                result['messages'].append({
                    'function': call.function,
                    'timestamp': call.timestamp,
                })

        return result

    def analyze_game_objects(self, object_array_addr=None, object_size=132,
                             max_objects=512):
        """Read game object array from memory.

        Args:
            object_array_addr: Address of the object array in memory.
            object_size: Size of each object in bytes.
            max_objects: Maximum number of objects to read.

        Returns list of {index, address, data}.
        """
        if object_array_addr is None:
            return []

        if self._wb._dbg is None:
            return []

        objects = []
        try:
            for i in range(max_objects):
                addr = object_array_addr + i * object_size
                data = self._wb._dbg.read_memory(addr, object_size)
                if any(b != 0 for b in data):
                    objects.append({'index': i, 'address': hex(addr), 'data': data.hex()})
        except Exception:
            pass

        return objects
