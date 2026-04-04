"""Core framework for firmware-toolkit."""

from .base_plugin import FirmwarePlugin, FormatVariant, PluginOption
from .plugin_manager import PluginManager
from .context import ProcessingContext

__all__ = ["FirmwarePlugin", "FormatVariant", "PluginManager", "PluginOption", "ProcessingContext"]
