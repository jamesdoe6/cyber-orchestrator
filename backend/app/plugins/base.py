"""Plugin contract.

Every tool/technique is a subclass of :class:`BasePlugin`. The core knows
nothing about individual tools — it only speaks this interface, so new modules
drop in without touching the engine.

A plugin provides:
  * ``meta``          — static description (slug, mode, privilege, ATT&CK, wizard steps);
  * ``build_argv``    — the command line to run (or ``None`` for a pure-Python module);
  * ``parse``         — turn raw output into a structured dict;
  * ``findings``      — derive Finding drafts from the structured dict.

Execution, scope enforcement, auditing and persistence are the engine's job,
not the plugin's — keeping plugins small and uniform.
"""
from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field

from ..models import Mode, Severity
from . import base as _self  # noqa: F401  (self-ref for type clarity)


@dataclass
class Param:
    name: str
    label: str
    type: str = "string"          # string | int | bool | choice | textarea
    required: bool = True
    default: object = None
    help: str = ""
    choices: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)  # free-text autocomplete (datalist)


@dataclass
class Step:
    """One stage of the guided assistant shown in the UI."""
    id: str
    title: str
    help: str
    params: list[str] = field(default_factory=list)   # Param names collected here
    expect: str = ""                                   # "what to expect" text


@dataclass
class PluginMeta:
    slug: str
    name: str
    mode: Mode
    category: str
    privilege: str                 # scope.PASSIVE | ACTIVE | OFFENSIVE
    description: str
    attack_techniques: list[str] = field(default_factory=list)
    params: list[Param] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    binary: str | None = None      # external binary this plugin wraps, if any

    def to_dict(self) -> dict:
        d = asdict(self)
        d["mode"] = self.mode.value
        return d


@dataclass
class FindingDraft:
    title: str
    severity: Severity = Severity.info
    description: str = ""
    asset: str = ""
    cvss: float | None = None
    attack_technique: str = ""
    remediation: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass
class ExecResult:
    raw_output: str
    exit_code: int | None
    command: str
    simulated: bool = False


class ToolRunner:
    """Thin, bounded wrapper around subprocess.

    * Enforces a timeout.
    * If the wrapped binary is absent, returns a clearly-flagged *simulated*
      result via the plugin's ``simulate`` hook, so the platform and its
      reporting/UI flow can be exercised on a host where the tool is not yet
      installed. Simulated runs are audited as such and never masquerade as
      real results.
    """

    def __init__(self, timeout: int = 600):
        self.timeout = timeout

    @staticmethod
    def available(binary: str | None) -> bool:
        return binary is not None and shutil.which(binary) is not None

    def run(self, argv: list[str]) -> ExecResult:
        proc = subprocess.run(  # noqa: S603 - argv is a list, never shell=True
            argv,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        return ExecResult(
            raw_output=(proc.stdout or "") + (proc.stderr or ""),
            exit_code=proc.returncode,
            command=" ".join(argv),
        )

    def stream(self, argv: list[str], on_line, control=None) -> ExecResult:
        """Run argv, invoking on_line(str) for each output line as it arrives.

        Lets the UI watch a long scan live. Still argv-only (never a shell) and
        still bounded by ``timeout``. If ``control`` is given, the live process is
        registered on it (so it can be killed) and cancellation is honored.
        """
        import time
        lines: list[str] = []
        start = time.monotonic()
        proc = subprocess.Popen(  # noqa: S603 - argv list, never shell=True
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        if control is not None:
            control.set_proc(proc)
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if control is not None and control.cancelled:
                    proc.kill()
                    on_line("[cancelled by operator]")
                    break
                if time.monotonic() - start > self.timeout:
                    proc.kill()
                    on_line("[timeout] killed after %ds" % self.timeout)
                    break
                line = line.rstrip("\n")
                lines.append(line)
                try:
                    on_line(line)
                except Exception:  # noqa: BLE001 - a bad subscriber must not kill the scan
                    pass
            proc.wait(timeout=self.timeout)
        finally:
            if proc.poll() is None:
                proc.kill()
        return ExecResult(raw_output="\n".join(lines), exit_code=proc.returncode,
                          command=" ".join(argv))


class BasePlugin(ABC):
    meta: PluginMeta

    def resolve_binary(self) -> str | None:
        """Absolute path of the wrapped tool, or None if absent.

        Override when a plugin must disambiguate a name clash (e.g. httpx the
        scanner vs. httpx the Python library CLI). Default: PATH lookup.
        """
        import shutil
        return shutil.which(self.meta.binary) if self.meta.binary else None

    def build_argv(self, params: dict) -> list[str] | None:
        """Return the command line, or None for a pure-Python plugin."""
        return None

    def simulate(self, params: dict) -> str:
        """Representative output used when the wrapped binary is missing."""
        return "[simulation] tool not installed; no real output produced."

    @abstractmethod
    def parse(self, raw_output: str, params: dict) -> dict:
        ...

    @abstractmethod
    def findings(self, parsed: dict, params: dict) -> list[FindingDraft]:
        ...

    # Pure-Python plugins (no external binary) override this instead of build_argv.
    def execute_python(self, params: dict) -> ExecResult:
        raise NotImplementedError
