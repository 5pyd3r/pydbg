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
    python devtools/static_analysis_cli.py callers target.exe --target 0x401000
    python devtools/static_analysis_cli.py gaps    target.exe

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
    """Who calls a function, by name of the function that contains the site.

    The kinds are printed with the count because a reference from a data slot
    is not a call and there is no function containing it. A number that mixes
    the two without saying so invites the reading that a vtable entry is a
    call site.
    """
    result = analyze_file(args.image)
    callers = result.callers_of(args.target)
    kinds = ", ".join(report.kind_name(kind)
                      for kind in result.ref_kinds_of(args.target))
    print(f"{args.target:#x} referenced from {len(callers)} site(s) "
          f"[{kinds or 'nothing'}]")
    for site in callers:
        owner = result.functions.containing(site)
        where = f" (in {owner:#x})" if owner is not None else ""
        print(f"    {site:#010x}{where}")
    return 0


def cmd_gaps(args):
    """What the reference index is known to be missing."""
    result = analyze_file(args.image)
    print(result.render_xref_gaps())
    return 0


def cmd_indirect(args):
    """Branches with no resolved target — the call graph's blind spots."""
    result = analyze_file(args.image)
    print(result.render_indirect_sites(limit=args.limit,
                                       calls_only=not args.all))
    return 0


def _load_workspace(image, path, create=False):
    """Open a workspace for 'image', creating it if asked and absent."""
    import os

    from pydbg.analysis import Workspace
    if path and os.path.exists(path):
        return Workspace.load(path, image)
    if create:
        workspace = Workspace.for_image(image)
        workspace.path = path
        return workspace
    return None


def cmd_names(args):
    result = analyze_file(args.image)
    workspace = _load_workspace(args.image, args.workspace)
    print(result.render_names(workspace=workspace, limit=args.limit,
                              source=args.source))
    return 0


def cmd_label(args):
    """Name an address and save it.

    The write half of the loop: an analysis takes half a minute and produces
    thousands of addresses, and the naming is done afterwards over hours.
    Without a way to save that, the hours are spent again every run.
    """
    if not args.workspace:
        print("--workspace is required: a name has to be saved somewhere")
        return 2
    workspace = _load_workspace(args.image, args.workspace, create=True)
    workspace.name(args.at, args.name)
    if args.comment:
        workspace.comment(args.at, args.comment)
    workspace.save()
    print(f"{args.at:#x} = {args.name}  (saved to {args.workspace})")
    return 0


def cmd_structures(args):
    """Base-register access profiles — the raw material for struct layouts."""
    result = analyze_file(args.image)
    workspace = _load_workspace(args.image, args.workspace)
    print(result.render_structures(workspace=workspace, limit=args.limit,
                                   function=args.function,
                                   min_offsets=args.min_offsets))
    return 0


def cmd_attribution(args):
    """Why the coverage and overlap numbers are what they are."""
    result = analyze_file(args.image)
    print(result.render_attribution(limit=args.limit))
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


def cmd_owners(args):
    """What an address belongs to — bounded, and naming which finding it is."""
    result = analyze_file(args.image)
    owner, kind = result.functions.owner_of(args.at)
    if owner is None:
        print(f"{args.at:#x}: owned by nothing ({kind})")
    else:
        print(f"{args.at:#x}: {kind} of the function at {owner:#x}")
    container = result.container_of(args.at)
    if container is not None:
        table, index = container
        where = "entry %d" % index if index is not None else "not slot-aligned"
        print(f"  inside a {table.kind} at {table.base:#x} "
              f"({table.count} slots, {where})")
    return 0


def cmd_boundary(args):
    """Whether an address starts an instruction, sits inside one, or neither."""
    result = analyze_file(args.image)
    print(result.boundary_of(args.at).render())
    return 0


def cmd_receiver(args):
    """Where the base register of the access at 'at' came from."""
    from pydbg.analysis import receiver_of
    result = analyze_file(args.image)
    note = receiver_of(result, args.at, base_reg=args.reg)
    if note is None:
        print(f"{args.at:#x} makes no base-register access")
        return 1
    print(note.render())
    if args.evidence:
        for rva in note.evidencing:
            print(f"  walked {rva:#x}")
    return 0


def cmd_tables(args):
    """The runs of indexed slots the sweep read, ascending by base."""
    result = analyze_file(args.image)
    if not result.slot_tables:
        print("no slot tables")
        return 0
    for table in result.slot_tables:
        start, end = table.span()
        shown = "at least %d" % table.count if table.truncated else str(table.count)
        referrer = f"{table.referrer:#x}" if table.referrer is not None else "-"
        print(f"{table.base:#x}..{end:#x}  {table.kind}  {shown} slots "
              f"of {table.stride}  named by {referrer}")
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
            # The flag matches what it means: --target for a lookup subject,
            # --at for a position to examine.
            child.add_argument(f"--{target_dest}", dest=target_dest,
                               type=_parse_int, required=True,
                               help="RVA, e.g. 0x401000")
        return child

    add("stats", cmd_stats)
    add("seeds", cmd_seeds)

    funcs = add("funcs", cmd_funcs)
    funcs.add_argument("--limit", type=int, default=None)

    xref = add("xref", cmd_xref)
    xref.add_argument("--target", type=_parse_int, default=None)
    xref.add_argument("--limit", type=int, default=8)

    add("callers", cmd_callers, target_dest="target")

    structures = add("structures", cmd_structures)
    structures.add_argument("--limit", type=int, default=10)
    structures.add_argument("--min-offsets", dest="min_offsets", type=int,
                            default=None)
    structures.add_argument("--function", type=_parse_int, default=None,
                            help="only profiles inside this function")
    structures.add_argument("--workspace", default=None)

    attribution = add("attribution", cmd_attribution)
    attribution.add_argument("--limit", type=int, default=10)

    names = add("names", cmd_names)
    names.add_argument("--limit", type=int, default=None)
    names.add_argument("--source", default=None,
                       help="only names from this source (export/import/auto)")
    names.add_argument("--workspace", default=None,
                       help="a saved workspace whose names win")

    label = add("label", cmd_label, target_dest="at")
    label.add_argument("--name", required=True)
    label.add_argument("--comment", default=None)
    label.add_argument("--workspace", required=True)

    indirect = add("indirect", cmd_indirect)
    indirect.add_argument("--limit", type=int, default=40)
    indirect.add_argument("--all", action="store_true",
                          help="include unresolved jumps, not just calls")
    add("gaps", cmd_gaps)
    add("cfg", cmd_cfg, target_dest="at")
    add("dot", cmd_dot, target_dest="at")

    add("owners", cmd_owners, target_dest="at")
    add("boundary", cmd_boundary, target_dest="at")
    receiver = add("receiver", cmd_receiver, target_dest="at")
    receiver.add_argument("--reg", default=None,
                          help="base register to ask about; the first "
                               "non-stack one by default")
    receiver.add_argument("--evidence", action="store_true",
                          help="list every instruction the walk looked at")
    add("tables", cmd_tables)

    listing = add("list", cmd_list, target_dest="at")
    listing.add_argument("--size", type=_parse_int, default=64)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    # A workspace that belongs to another binary is a refusal, not a crash:
    # the message is the useful part and a traceback buries it.
    from pydbg.analysis import WorkspaceError
    try:
        return args.handler(args)
    except WorkspaceError as error:
        print(f"workspace error: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
