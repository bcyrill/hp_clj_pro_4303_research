"""Base plugin interface for firmware format handlers."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, BinaryIO


class FormatVariant(Enum):
    """Identifies a specific variant/representation of a data format.

    Plugins define their own variant values.  The framework uses them
    to route unpack/pack requests to the right conversion logic.
    """
    pass


@dataclass
class PluginOption:
    """Describes a CLI option that a plugin registers.

    For boolean flags (the default), passing the flag on the command
    line sets ``kwarg_name=kwarg_value`` in the ``**kwargs`` dict
    forwarded to the plugin's :meth:`~FirmwarePlugin.pack` or
    :meth:`~FirmwarePlugin.unpack` method.

    For value-bearing options, set ``takes_value=True`` (and optionally
    ``metavar``).  The CLI will add the option with ``type=str`` and
    forward the user-supplied string as ``kwarg_name=<user_value>``.
    """
    flag: str                  # CLI flag, e.g. "--no-ecc" or "--password"
    description: str           # argparse help text
    kwarg_name: str            # key passed to pack/unpack kwargs
    kwarg_value: Any = True    # value to set when a boolean flag is present
    default: Any = None        # default when the flag is absent
    applies_to: str = "pack"   # "pack", "unpack", or "both"
    takes_value: bool = False  # True → expects a string argument
    metavar: str | None = None # argparse metavar for value-bearing options


@dataclass
class ConversionInfo:
    """Describes what a specific conversion does."""
    source_variant: str
    target_variant: str
    description: str
    lossy: bool = False
    available: bool = True
    missing_deps: list[str] = field(default_factory=list)


@dataclass
class PluginInfo:
    """Metadata about a firmware plugin."""
    name: str
    description: str
    version: str
    format_id: str
    supported_variants: list[str] = field(default_factory=list)
    conversions: list[ConversionInfo] = field(default_factory=list)
    ksy_files: list[str] = field(default_factory=list)


@dataclass
class UnpackResult:
    """Result of an unpack operation."""
    output_path: Path
    source_variant: str
    target_variant: str
    source_hash: str
    output_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PackResult:
    """Result of a pack operation."""
    output_path: Path
    source_variant: str
    target_variant: str
    source_hash: str
    output_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)


def file_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class FirmwarePlugin(ABC):
    """Abstract base class for firmware format plugins.

    Each plugin handles one *format family* (e.g. a specific NAND chip)
    and can convert between *variants* of that format (e.g. with-OOB
    vs. without-OOB).

    Plugins are discovered automatically by the :class:`PluginManager`.
    To create a new plugin, subclass this class and place it inside the
    ``firmware_toolkit/plugins/<plugin_name>/`` directory.
    """

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @abstractmethod
    def get_info(self) -> PluginInfo:
        """Return plugin metadata."""
        ...

    # ------------------------------------------------------------------
    # Plugin-specific CLI options
    # ------------------------------------------------------------------

    def get_options(self) -> list[PluginOption]:
        """Return CLI options this plugin wants to register.

        Override to expose plugin-specific flags (e.g. ``--no-ecc``)
        that the CLI will add to its ``pack`` / ``unpack`` sub-commands.
        The default implementation returns an empty list.
        """
        return []

    # ------------------------------------------------------------------
    # Identification
    # ------------------------------------------------------------------

    @abstractmethod
    def identify(self, path: Path) -> str | None:
        """Try to identify the format variant of *path*.

        Returns the variant name string if recognised, or ``None`` if
        this plugin does not handle the given file.
        """
        ...

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    @abstractmethod
    def get_conversions(self) -> list[ConversionInfo]:
        """List every source→target conversion this plugin supports."""
        ...

    @abstractmethod
    def unpack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> UnpackResult:
        """Unpack / convert *input_path* and write the result to *output_path*.

        If *source_variant* is ``None`` the plugin should auto-detect
        it.  If *target_variant* is ``None`` the plugin should pick a
        sensible default.
        """
        ...

    @abstractmethod
    def pack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> PackResult:
        """Pack / convert *input_path* back into the target variant.

        The semantics mirror :meth:`unpack` but in the opposite
        direction.
        """
        ...

    # ------------------------------------------------------------------
    # Optional: Kaitai struct parsing helpers
    # ------------------------------------------------------------------

    def parse(self, path: Path, variant: str | None = None) -> Any:
        """Parse *path* using the appropriate Kaitai Struct parser.

        Override to provide parsed access to the file contents.
        Returns a Kaitai Struct object, or raises ``NotImplementedError``
        if the plugin does not support direct parsing.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement parse()"
        )
