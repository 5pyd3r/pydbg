"""Analysis workbench: orchestrates all analysis modules."""

import os


class AnalysisWorkbench:
    """Game binary analysis workbench.

    Coordinates PE analysis, API interception, resource extraction,
    execution tracing, and report generation.
    """

    def __init__(self, target_exe):
        self._target = target_exe
        self._dbg = None
        self._stealth = None
        self._interceptor = None
        self._tracer = None
        self._pe = None

    def setup(self, stealth=True):
        """Initialize the analysis environment.

        Args:
            stealth: If True, prepare anti-detection measures.
        """
        from ..core.debugger import Debugger
        self._dbg = Debugger()
        if stealth:
            from ..stealth.anti_aware import AntiAware
            self._stealth = AntiAware(self._dbg._session)

    def load_and_analyze_pe(self):
        """Static analysis: parse PE structure, imports, exports.

        Returns dict with keys: sections, imports, exports, etc.
        """
        from ..pe import PE

        if os.path.isfile(self._target):
            self._pe = PE.from_file(self._target)
        else:
            raise FileNotFoundError(f"Target not found: {self._target}")

        sections = []
        for sec in self._pe.sections:
            sections.append({
                'name': sec.name,
                'virtual_address': sec.virtual_address,
                'virtual_size': sec.virtual_size,
                'size_of_raw_data': sec.size_of_raw_data,
                'characteristics': sec.characteristics,
            })

        imports = []
        for imp in self._pe.imports:
            imports.append({
                'dll': imp.dll_name,
                'name': imp.name,
                'ordinal': imp.ordinal,
                'rva': imp.rva,
            })

        exports = []
        for exp in self._pe.exports:
            exports.append({
                'name': exp.name,
                'ordinal': exp.ordinal,
                'rva': exp.rva,
                'forwarder': exp.forwarder,
            })

        return {
            'machine': hex(self._pe.file_header.machine),
            'entry_point': hex(self._pe.optional_header.entry_point_rva),
            'image_base': hex(self._pe.optional_header.image_base),
            'sections': sections,
            'imports': imports,
            'exports': exports,
        }

    def setup_interception(self, preset_name="ddraw"):
        """Set up API interception with a named preset.

        Args:
            preset_name: One of 'ddraw', 'dsound', 'win32'.

        Returns:
            The configured APIInterceptor instance.

        Raises:
            ValueError: If the preset name is not recognized.
            RuntimeError: If setup() has not been called yet.
        """
        if self._dbg is None:
            raise RuntimeError("Call setup() before setup_interception()")

        from ..intercept.api_hook import APIInterceptor
        from ..intercept.presets import load_preset

        preset = load_preset(preset_name)
        self._interceptor = APIInterceptor(self._dbg._session)
        self._interceptor.intercept_module(
            f"{preset_name}.dll" if preset_name in ("ddraw", "dsound") else preset_name,
            preset,
        )
        return self._interceptor

    def extract_resources(self, output_dir=None):
        """Extract resources from the PE file.

        Args:
            output_dir: Directory to write extracted files. If None, returns data only.

        Returns list of extracted file paths (or ResourceEntry list if no output_dir).
        """
        from ..resource.pe_resource import PEResourceParser

        if self._pe is None:
            self.load_and_analyze_pe()

        parser = PEResourceParser(self._pe)
        resources = parser.parse()

        if output_dir is None:
            return resources

        os.makedirs(output_dir, exist_ok=True)
        return parser.extract_all(output_dir)

    def generate_report(self, output_path):
        """Generate a Markdown analysis report.

        Parses the PE if not already loaded, then writes sections for PE info,
        imports, exports, resources, API call summary, and execution trace.

        Args:
            output_path: File path to write the Markdown report to.
        """
        from datetime import datetime, timezone

        # Ensure PE is loaded
        if self._pe is None:
            self.load_and_analyze_pe()

        info = self._build_pe_info()

        lines = [
            f"# Analysis Report: {os.path.basename(self._target)}",
            "",
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## PE Information",
            "",
            f"- **Machine**: {info['machine']}",
            f"- **Entry Point RVA**: {info['entry_point']}",
            f"- **Image Base**: {info['image_base']}",
            "",
            "## Sections",
            "",
            "| Name | Virtual Address | Virtual Size | Raw Size | Characteristics |",
            "|------|----------------|-------------|----------|----------------|",
        ]

        for s in info["sections"]:
            lines.append(
                f"| {s['name']} | 0x{s['virtual_address']:X} | 0x{s['virtual_size']:X} "
                f"| 0x{s['size_of_raw_data']:X} | 0x{s['characteristics']:X} |"
            )

        lines += ["", "## Imports", ""]

        if info["imports"]:
            lines += [
                "| DLL | Function | Ordinal | RVA |",
                "|-----|----------|---------|-----|",
            ]
            for imp in info["imports"]:
                name = imp["name"] or f"ordinal {imp['ordinal']}"
                lines.append(
                    f"| {imp['dll']} | {name} | {imp['ordinal']} | 0x{imp['rva']:X} |"
                )
        else:
            lines.append("No imports found.")

        lines += ["", "## Exports", ""]

        if info["exports"]:
            lines += [
                "| Name | Ordinal | RVA | Forwarder |",
                "|------|---------|-----|-----------|",
            ]
            for exp in info["exports"]:
                name = exp["name"] or f"ordinal {exp['ordinal']}"
                fwd = exp["forwarder"] or ""
                lines.append(
                    f"| {name} | {exp['ordinal']} | 0x{exp['rva']:X} | {fwd} |"
                )
        else:
            lines.append("No exports found.")

        # Resources
        try:
            from ..resource.pe_resource import PEResourceParser
            parser = PEResourceParser(self._pe)
            entries = parser.parse()
            if entries:
                lines += ["", "## Resources", ""]
                lines += [
                    "| Type | Type Name | Name ID | Language | Size |",
                    "|------|-----------|---------|----------|------|",
                ]
                for e in entries:
                    lines.append(
                        f"| {e.type_id} | {e.type_name} | {e.name_id} "
                        f"| 0x{e.language_id:04X} | {e.data_size} |"
                    )
            else:
                lines += ["", "## Resources", "", "No resources found."]
        except Exception:
            lines += ["", "## Resources", "", "Could not parse resources."]

        # API Calls
        if self._interceptor is not None:
            counts = self._interceptor.get_call_count()
            if counts:
                lines += ["", "## API Call Summary", ""]
                for func, count in sorted(counts.items(), key=lambda x: -x[1]):
                    lines.append(f"- {func}: {count}")

        # Trace
        if self._tracer is not None:
            events = self._tracer.get_events()
            heatmap = self._tracer.get_execution_heatmap()
            lines += ["", "## Execution Trace", ""]
            lines.append(f"- Total events: {len(events)}")
            lines.append(f"- Unique addresses: {len(heatmap)}")
            if heatmap:
                top = sorted(heatmap.items(), key=lambda x: -x[1])[:10]
                lines.append("- Top addresses:")
                for addr, count in top:
                    lines.append(f"  - 0x{addr:X}: {count} executions")

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')

    def _build_pe_info(self):
        """Build PE info dict from the already-parsed PE object."""
        pe = self._pe
        machine_map = {0x14C: "i386", 0x8664: "AMD64", 0xAA64: "ARM64"}
        machine = machine_map.get(pe.file_header.machine,
                                  f"0x{pe.file_header.machine:04X}")

        sections = [
            {
                "name": s.name,
                "virtual_address": s.virtual_address,
                "virtual_size": s.virtual_size,
                "size_of_raw_data": s.size_of_raw_data,
                "characteristics": s.characteristics,
            }
            for s in pe.sections
        ]

        imports = [
            {
                "dll": imp.dll_name,
                "name": imp.name,
                "ordinal": imp.ordinal,
                "rva": imp.rva,
            }
            for imp in pe.imports
        ]

        exports = [
            {
                "name": exp.name,
                "ordinal": exp.ordinal,
                "rva": exp.rva,
                "forwarder": exp.forwarder,
            }
            for exp in pe.exports
        ]

        return {
            "machine": machine,
            "entry_point": pe.optional_header.entry_point_rva,
            "image_base": pe.optional_header.image_base,
            "sections": sections,
            "imports": imports,
            "exports": exports,
        }
