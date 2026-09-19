"""static_analysis_cli — run pydbg's analyzer over an image and print results.

A manual validation harness rather than a test. The numbers worth checking a
port against come from a separate prototype run over three real targets, and
those live in a different repository that CI does not check out — so this is
how those numbers get compared by hand:

    python devtools/static_analysis_cli.py stats   target.exe
    python devtools/static_analysis_cli.py funcs   target.exe --limit 40
    python devtools/static_analysis_cli.py xref    target.exe --target 0x401000
    python devtools/static_analysis_cli.py cfg     target.exe --at 0x401000
    python devtools/static_analysis_cli.py list    target.exe --at 0x401000 --size 64
    python devtools/static_analysis_cli.py dot     target.exe --at 0x401000
    python devtools/static_analysis_cli.py seeds   target.exe

Everything is printed in a stable order so two runs can be diffed.
"""

import argparse
import sys

from pydbg.analysis import AnalyzedImage, SeedProvider, analyze_file
from pydbg.analysis import report


def _parse_int(text):
    return int(text, 0)


def cmd_stats(args):
    result = analyze_file(args.image)
    print(result.render_summary())
    return 0


def cmd_seeds(args):
    seeds = SeedProvider(AnalyzedImage.from_file(args.image)).collect()
    classes = seeds.classes()
    print(f"{'class':22s} {'count':>8s}")
    for name in sorted(classes):
        print(f"{name:22s} {classes[name]:8d}")
    print(f"{'confident total':22s} {len(seeds.confident):8d}")
    print(f"{'tentative total':22s} {len(seeds.tentative):8d}")
    return 0


def cmd_funcs(args):
    result = analyze_file(args.image)
    print(result.render_functions(limit=args.limit))
    return 0


def cmd_xref(args):
    result = analyze_file(args.image)
    print(result.render_xrefs(target=args.target, limit=args.limit))
    return 0


def cmd_callers(args):
    """Who calls a function, by name of the function that contains the site."""
    result = analyze_file(args.image)
    callers = result.callers_of(args.target)
    print(f"{args.target:#x} called from {len(callers)} site(s)")
    for site in callers:
        owner = result.functions.containing(site)
        where = f" (in {owner:#x})" if owner is not None else ""
        print(f"    {site:#010x}{where}")
    return 0


def cmd_indirect(args):
    """Branches with no resolved target — the call graph's blind spots."""
    result = analyze_file(args.image)
    print(result.render_indirect_sites(limit=args.limit,
                                       calls_only=not args.all))
    return 0


def cmd_cfg(args):
    result = analyze_file(args.image)
    cfg = result.cfg_of(args.at)
    if cfg is None:
        print(f"{args.at:#x} is not inside any recovered function")
        return 1
    print(report.render_cfg(cfg))
    return 0


def cmd_dot(args):
    from pydbg.analysis import cfg_to_dot
    result = analyze_file(args.image)
    cfg = result.cfg_of(args.at)
    if cfg is None:
        print(f"{args.at:#x} is not inside any recovered function")
        return 1
    print(cfg_to_dot(cfg))
    return 0


def cmd_list(args):
    result = analyze_file(args.image)
    print(result.render_listing(args.at, args.size))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name, handler, target_dest=None):
        """Register a subcommand. 'target_dest' adds a required --target."""
        child = sub.add_parser(name)
        child.add_argument("image")
        child.set_defaults(handler=handler)
        if target_dest:
            child.add_argument("--target", dest=target_dest, type=_parse_int,
                               required=True, help="RVA, e.g. 0x401000")
        return child

    add("stats", cmd_stats)
    add("seeds", cmd_seeds)

    funcs = add("funcs", cmd_funcs)
    funcs.add_argument("--limit", type=int, default=None)

    xref = add("xref", cmd_xref)
    xref.add_argument("--target", type=_parse_int, default=None)
    xref.add_argument("--limit", type=int, default=8)

    add("callers", cmd_callers, target_dest="target")

    indirect = add("indirect", cmd_indirect)
    indirect.add_argument("--limit", type=int, default=40)
    indirect.add_argument("--all", action="store_true",
                          help="include unresolved jumps, not just calls")
    add("cfg", cmd_cfg, target_dest="at")
    add("dot", cmd_dot, target_dest="at")

    listing = add("list", cmd_list, target_dest="at")
    listing.add_argument("--size", type=_parse_int, default=64)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
