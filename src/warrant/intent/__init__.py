"""Intent: turning what a person asked for into a checkable scope (milestone M1).

    contract.py   Catalog and ScopeContract - the vocabulary, and the contract itself
    compiler.py   IntentCompiler - one language-model call, request -> contract
    eval.py       measuring the compiler against hand-labeled cases

Typical use:

    from warrant.intent import Catalog, IntentCompiler

    compiler = IntentCompiler(Catalog.load("catalog.json"))
    warrant.configure(store="warrant.db", intent=compiler)

    with warrant.session(principal="sarah@company.com",
                         request="clean up our old sales records",
                         ceiling=sarahs_real_permissions):
        ...

The language-model call needs the optional extra
(pip install 'warrant-provenance[intent]') and an Anthropic API key in
ANTHROPIC_API_KEY. Everything else here works without either.
"""

from .compiler import (
    DEFAULT_MODEL,
    PROMPT_VERSION,
    ClaudeBackend,
    CompiledIntent,
    IntentCompiler,
    IntentError,
    IntentRefused,
)
from .contract import Catalog, CatalogEntry, ScopeContract

__all__ = [
    "Catalog", "CatalogEntry", "ScopeContract",
    "IntentCompiler", "CompiledIntent", "ClaudeBackend",
    "IntentError", "IntentRefused", "PROMPT_VERSION", "DEFAULT_MODEL",
]
