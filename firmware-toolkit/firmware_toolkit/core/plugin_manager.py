"""Plugin discovery and management."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Any

from .base_plugin import FirmwarePlugin, PluginInfo

logger = logging.getLogger(__name__)


class PluginManager:
    """Discovers, loads and manages firmware plugins.

    Plugins are Python packages located under
    ``firmware_toolkit/plugins/``.  Each package must expose a
    ``plugin.py`` module containing a class that inherits from
    :class:`FirmwarePlugin`.

    External plugins can be registered at runtime via :meth:`register`.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, FirmwarePlugin] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self, package_name: str = "firmware_toolkit.plugins") -> None:
        """Auto-discover plugins under *package_name*.

        Each sub-package is expected to contain a ``plugin`` module
        with a ``Plugin`` class (subclass of :class:`FirmwarePlugin`).
        """
        try:
            package = importlib.import_module(package_name)
        except ModuleNotFoundError:
            logger.warning("Plugin package %s not found", package_name)
            return

        package_path = getattr(package, "__path__", None)
        if package_path is None:
            return

        for importer, modname, ispkg in pkgutil.iter_modules(package_path):
            if not ispkg:
                continue
            fqn = f"{package_name}.{modname}.plugin"
            try:
                mod = importlib.import_module(fqn)
            except Exception as exc:
                logger.warning("Failed to import plugin %s: %s", fqn, exc)
                continue

            plugin_cls = getattr(mod, "Plugin", None)
            if plugin_cls is None:
                logger.warning("No 'Plugin' class in %s", fqn)
                continue

            if not issubclass(plugin_cls, FirmwarePlugin):
                logger.warning(
                    "%s.Plugin does not inherit FirmwarePlugin", fqn
                )
                continue

            instance = plugin_cls()
            info = instance.get_info()
            self._plugins[info.format_id] = instance
            logger.info(
                "Loaded plugin: %s v%s (%s)",
                info.name, info.version, info.format_id,
            )

    # ------------------------------------------------------------------
    # Manual registration
    # ------------------------------------------------------------------

    def register(self, plugin: FirmwarePlugin) -> None:
        """Register an external plugin instance."""
        info = plugin.get_info()
        self._plugins[info.format_id] = plugin
        logger.info("Registered plugin: %s (%s)", info.name, info.format_id)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_plugin(self, format_id: str) -> FirmwarePlugin | None:
        """Return the plugin for *format_id*, or ``None``."""
        return self._plugins.get(format_id)

    def list_plugins(self) -> list[PluginInfo]:
        """Return metadata for every loaded plugin."""
        return [p.get_info() for p in self._plugins.values()]

    def identify(self, path: Path) -> list[tuple[str, str]]:
        """Ask every plugin to identify *path*.

        Returns a list of ``(format_id, variant)`` tuples for every
        plugin that recognises the file.
        """
        results: list[tuple[str, str]] = []
        for fmt_id, plugin in self._plugins.items():
            try:
                variant = plugin.identify(path)
                if variant is not None:
                    results.append((fmt_id, variant))
            except Exception as exc:
                logger.debug(
                    "Plugin %s raised during identify: %s", fmt_id, exc
                )
        return results

    @property
    def plugins(self) -> dict[str, FirmwarePlugin]:
        """Direct access to loaded plugins dict."""
        return dict(self._plugins)
