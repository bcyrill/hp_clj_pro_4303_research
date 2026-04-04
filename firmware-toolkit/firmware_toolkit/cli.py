"""Command-line interface for firmware-toolkit."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from firmware_toolkit.core import PluginManager, ProcessingContext
from firmware_toolkit.core.base_plugin import PluginOption

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _flag_to_attr(flag: str) -> str:
    """Convert a CLI flag like ``--no-ecc`` to its argparse attribute ``no_ecc``."""
    return flag.lstrip("-").replace("-", "_")


def _collect_plugin_kwargs(
    plugin: object,
    args: argparse.Namespace,
    command: str,
) -> dict:
    """Build the **kwargs dict from registered plugin options."""
    extra: dict = {}
    for opt in plugin.get_options():
        if opt.applies_to not in (command, "both"):
            continue
        attr = _flag_to_attr(opt.flag)
        value = getattr(args, attr, opt.default)
        if opt.takes_value:
            # Value-bearing option: forward the actual user-supplied
            # string (or default) directly.
            if value is not None:
                extra[opt.kwarg_name] = value
        else:
            # Boolean flag: set kwarg_value when flag is present.
            if value != opt.default:
                extra[opt.kwarg_name] = opt.kwarg_value
    return extra


def _register_plugin_options(
    mgr: PluginManager,
    subparsers: dict[str, argparse.ArgumentParser],
) -> None:
    """Query every loaded plugin for options and add them to the sub-parsers."""
    seen_flags: dict[str, set[str]] = {cmd: set() for cmd in subparsers}

    for info in mgr.list_plugins():
        plugin = mgr.get_plugin(info.format_id)
        options = plugin.get_options()
        if not options:
            continue

        for opt in options:
            targets: list[str] = (
                ["pack", "unpack"] if opt.applies_to == "both"
                else [opt.applies_to]
            )
            for cmd in targets:
                sp = subparsers.get(cmd)
                if sp is None:
                    continue
                if opt.flag in seen_flags[cmd]:
                    continue  # already registered by another plugin
                seen_flags[cmd].add(opt.flag)

                if opt.takes_value:
                    sp.add_argument(
                        opt.flag,
                        type=str,
                        default=opt.default,
                        metavar=opt.metavar or opt.kwarg_name.upper(),
                        help=f"{opt.description} [{info.name}]",
                    )
                else:
                    sp.add_argument(
                        opt.flag,
                        action="store_true",
                        default=opt.default,
                        help=f"{opt.description} [{info.name}]",
                    )


# ── Sub-commands ─────────────────────────────────────────────────────


def cmd_list_plugins(mgr: PluginManager, args: argparse.Namespace) -> None:
    """List all available plugins."""
    plugins = mgr.list_plugins()
    if not plugins:
        print("No plugins loaded.")
        return
    for info in plugins:
        print(f"\n{'=' * 60}")
        print(f"  Plugin:      {info.name} v{info.version}")
        print(f"  Format ID:   {info.format_id}")
        print(f"  Description: {info.description}")
        print(f"  Variants:    {', '.join(info.supported_variants)}")
        print(f"  KSY files:   {', '.join(info.ksy_files)}")
        if info.conversions:
            print(f"  Conversions:")
            for c in info.conversions:
                tags = ""
                if c.lossy:
                    tags += " [lossy]"
                if not c.available:
                    deps = ", ".join(c.missing_deps) if c.missing_deps else "unknown"
                    tags += f" [unavailable — missing: {deps}]"
                print(f"    - {c.description}{tags}")
        plugin = mgr.get_plugin(info.format_id)
        options = plugin.get_options()
        if options:
            print(f"  Options:")
            for opt in options:
                print(f"    {opt.flag}: {opt.description} (applies to: {opt.applies_to})")
    print()


def cmd_identify(mgr: PluginManager, args: argparse.Namespace) -> None:
    """Identify a firmware file."""
    path = Path(args.input)
    if not path.exists():
        print(f"Error: {path} does not exist", file=sys.stderr)
        sys.exit(1)

    results = mgr.identify(path)
    if not results:
        print(f"No plugin recognised {path.name}")
        return

    for format_id, variant in results:
        plugin = mgr.get_plugin(format_id)
        info = plugin.get_info()
        print(f"  Format:  {info.name} ({format_id})")
        print(f"  Variant: {variant}")


def cmd_unpack(mgr: PluginManager, args: argparse.Namespace) -> None:
    """Unpack a firmware file."""
    input_path = Path(args.input)
    # A trailing slash signals that the user wants a directory, even if it
    # doesn't exist yet.  Create it so that plugins can rely on .is_dir().
    if args.output and args.output.endswith(("/", "\\")):
        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)
    else:
        output_path = Path(args.output) if args.output else None

    if not input_path.exists():
        print(f"Error: {input_path} does not exist", file=sys.stderr)
        sys.exit(1)

    # Resolve plugin
    if args.format:
        plugin = mgr.get_plugin(args.format)
        if plugin is None:
            print(f"Error: unknown format '{args.format}'", file=sys.stderr)
            sys.exit(1)
    else:
        results = mgr.identify(input_path)
        if not results:
            print(f"Error: cannot identify {input_path.name}", file=sys.stderr)
            sys.exit(1)
        format_id, _ = results[0]
        plugin = mgr.get_plugin(format_id)

    # Default output name
    if output_path is None:
        output_path = input_path.with_suffix(".unpacked.bin")

    extra_kwargs = _collect_plugin_kwargs(plugin, args, "unpack")

    try:
        result = plugin.unpack(
            input_path, output_path,
            source_variant=args.source_variant,
            target_variant=args.target_variant,
            **extra_kwargs,
        )
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Save context for re-packing
    ctx = ProcessingContext()
    ctx.push_unpack(result, plugin.get_info().format_id)
    ctx_dir = output_path if output_path.is_dir() else output_path.parent
    ctx.save(ctx_dir)

    print(f"\nUnpacked successfully:")
    print(f"  Input:   {input_path} ({result.source_variant})")
    print(f"  Output:  {output_path} ({result.target_variant})")
    print(f"  SHA-256: {result.output_hash[:16]}...")
    for k, v in result.metadata.items():
        print(f"  {k}: {v}")


def cmd_pack(mgr: PluginManager, args: argparse.Namespace) -> None:
    """Pack a firmware file."""
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else None

    if not input_path.exists():
        print(f"Error: {input_path} does not exist", file=sys.stderr)
        sys.exit(1)

    # Resolve candidate plugins
    if args.format:
        plugin = mgr.get_plugin(args.format)
        if plugin is None:
            print(f"Error: unknown format '{args.format}'", file=sys.stderr)
            sys.exit(1)
        candidates = [(args.format, None)]
    else:
        candidates = mgr.identify(input_path)
        if not candidates:
            print(f"Error: cannot identify {input_path.name}", file=sys.stderr)
            sys.exit(1)

    if output_path is None:
        output_path = input_path.with_suffix(".packed.bin")

    # Try each matching plugin until one succeeds.  This resolves
    # ambiguity when multiple plugins identify the same file (e.g. a
    # 512 MB NAND image matches both the partition-layout plugin and
    # the NAND-chip plugin, but only the latter can pack it).

    last_error: Exception | None = None
    for fmt_id, _ in candidates:
        plugin = mgr.get_plugin(fmt_id)
        extra_kwargs = _collect_plugin_kwargs(plugin, args, "pack")
        try:
            result = plugin.pack(
                input_path, output_path,
                source_variant=args.source_variant,
                target_variant=args.target_variant,
                **extra_kwargs,
            )
            break
        except (ValueError, NotImplementedError, RuntimeError) as exc:
            last_error = exc
            logger.debug("Plugin %s declined pack: %s", fmt_id, exc)
            continue
    else:
        print(f"Error: {last_error}", file=sys.stderr)
        sys.exit(1)

    print(f"\nPacked successfully:")
    print(f"  Input:   {input_path} ({result.source_variant})")
    print(f"  Output:  {output_path} ({result.target_variant})")
    print(f"  SHA-256: {result.output_hash[:16]}...")
    for k, v in result.metadata.items():
        print(f"  {k}: {v}")


def cmd_conversions(mgr: PluginManager, args: argparse.Namespace) -> None:
    """List all available conversions."""
    for info in mgr.list_plugins():
        plugin = mgr.get_plugin(info.format_id)
        conversions = plugin.get_conversions()
        if conversions:
            print(f"\n{info.name} ({info.format_id}):")
            for c in conversions:
                arrow = "→"
                tags = ""
                if c.lossy:
                    tags += " [lossy]"
                if not c.available:
                    deps = ", ".join(c.missing_deps) if c.missing_deps else "unknown"
                    tags += f" [unavailable — missing: {deps}]"
                print(f"  {c.source_variant} {arrow} {c.target_variant}{tags}")
                print(f"    {c.description}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="firmware-toolkit",
        description="Extensible firmware unpacking, patching and packing toolkit",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── list ──
    sub.add_parser("list", help="List loaded plugins")

    # ── identify ──
    p_id = sub.add_parser("identify", help="Identify a firmware file")
    p_id.add_argument("input", help="Path to firmware file")

    # ── conversions ──
    sub.add_parser("conversions", help="List all available conversions")

    # ── unpack ──
    p_unpack = sub.add_parser("unpack", help="Unpack a firmware file")
    p_unpack.add_argument("input", help="Input firmware file")
    p_unpack.add_argument("-o", "--output", help="Output file path")
    p_unpack.add_argument("-f", "--format", help="Force format plugin ID")
    p_unpack.add_argument("-s", "--source-variant", help="Source variant override")
    p_unpack.add_argument("-t", "--target-variant", help="Target variant override")

    # ── pack ──
    p_pack = sub.add_parser("pack", help="Pack a firmware file")
    p_pack.add_argument("input", help="Input firmware file")
    p_pack.add_argument("-o", "--output", help="Output file path")
    p_pack.add_argument("-f", "--format", help="Force format plugin ID")
    p_pack.add_argument("-s", "--source-variant", help="Source variant override")
    p_pack.add_argument("-t", "--target-variant", help="Target variant override")

    # ── Discover plugins and register their CLI options ──
    # We suppress logging during discovery so that --help works cleanly.
    logging.disable(logging.CRITICAL)
    mgr = PluginManager()
    mgr.discover()
    logging.disable(logging.NOTSET)

    _register_plugin_options(mgr, {"pack": p_pack, "unpack": p_unpack})

    # ── Parse args ──
    args = parser.parse_args()
    _setup_logging(args.verbose)

    # Re-discover with logging enabled (plugins are already cached)
    logger.debug("Plugin manager has %d plugins loaded", len(mgr.plugins))

    if args.command == "list":
        cmd_list_plugins(mgr, args)
    elif args.command == "identify":
        cmd_identify(mgr, args)
    elif args.command == "conversions":
        cmd_conversions(mgr, args)
    elif args.command == "unpack":
        cmd_unpack(mgr, args)
    elif args.command == "pack":
        cmd_pack(mgr, args)


if __name__ == "__main__":
    main()
