"""Processing context for layered firmware structures."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .base_plugin import UnpackResult, PackResult

logger = logging.getLogger(__name__)


@dataclass
class LayerInfo:
    """Tracks one unpacking layer in a processing chain."""
    format_id: str
    source_variant: str
    target_variant: str
    source_path: str
    output_path: str
    metadata: dict[str, Any] = field(default_factory=dict)


class ProcessingContext:
    """Tracks a chain of unpack/pack operations for layered formats.

    Firmware images are often layered — e.g. a NAND dump contains a
    filesystem image which contains individual files.  The
    ``ProcessingContext`` records the full unpack chain so that it can
    be reversed for packing.

    The context is serialised as a JSON manifest alongside the unpacked
    data, enabling fully automated re-packing.
    """

    MANIFEST_NAME = ".firmware-toolkit.json"

    def __init__(self) -> None:
        self.layers: list[LayerInfo] = []

    # ------------------------------------------------------------------
    # Layer tracking
    # ------------------------------------------------------------------

    def push_unpack(self, result: UnpackResult, format_id: str) -> None:
        """Record an unpack step."""
        self.layers.append(
            LayerInfo(
                format_id=format_id,
                source_variant=result.source_variant,
                target_variant=result.target_variant,
                source_path=str(result.output_path),
                output_path=str(result.output_path),
                metadata=result.metadata,
            )
        )

    def pop_for_pack(self) -> LayerInfo | None:
        """Pop the most recent layer (LIFO) for re-packing."""
        if self.layers:
            return self.layers.pop()
        return None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def save(self, directory: Path) -> Path:
        """Write the manifest to *directory*."""
        manifest_path = directory / self.MANIFEST_NAME
        data = {
            "version": 1,
            "layers": [asdict(l) for l in self.layers],
        }
        manifest_path.write_text(json.dumps(data, indent=2))
        logger.info("Saved processing manifest to %s", manifest_path)
        return manifest_path

    @classmethod
    def load(cls, directory: Path) -> "ProcessingContext":
        """Load a manifest from *directory*."""
        manifest_path = directory / cls.MANIFEST_NAME
        data = json.loads(manifest_path.read_text())
        ctx = cls()
        for layer_data in data.get("layers", []):
            ctx.layers.append(LayerInfo(**layer_data))
        return ctx
