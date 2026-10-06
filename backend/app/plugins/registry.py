"""Plugin discovery and registry.

Plugins register themselves by subclassing BasePlugin in a module under
``app.plugins.attack`` or ``app.plugins.defense``. ``load_all()`` imports those
packages and indexes every concrete plugin by slug.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from .base import BasePlugin

_REGISTRY: dict[str, BasePlugin] = {}


def _discover(package_name: str) -> None:
    package = importlib.import_module(package_name)
    for mod in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package_name}.{mod.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BasePlugin) and obj is not BasePlugin and not inspect.isabstract(obj):
                instance = obj()
                _REGISTRY[instance.meta.slug] = instance


def load_all() -> None:
    _REGISTRY.clear()
    _discover("app.plugins.attack")
    _discover("app.plugins.defense")


def all_plugins() -> list[BasePlugin]:
    if not _REGISTRY:
        load_all()
    return list(_REGISTRY.values())


def get(slug: str) -> BasePlugin | None:
    if not _REGISTRY:
        load_all()
    return _REGISTRY.get(slug)
