"""OPTIONAL LLM assistant hook for AGENT FINDER.

HONEST AUTH MODEL (read this before "plugging an LLM in"):
Two supported transports, checked in this order:

  1. SESSION/CLI-BASED (no API key): any shell command that reads the
     prompt on STDIN and prints the answer to STDOUT:

         export AGENT_FINDER_LLM_CMD="your-cli --print"

     This is the slot for "use the login I already have" -- e.g. if the
     ZCode desktop app ships a headless CLI driven by your email-login
     session, point this at it. NOTE (2026-08-17): the current ZCode
     client is a desktop app with no callable headless mode, and its
     stored session credentials are private to that app -- they are
     never extracted or reused here. Also fits claude/gemini-style CLI
     tools or a local model launcher.
  2. API-KEY (OpenAI-compatible endpoint, incl. local gateways):

         export AGENT_FINDER_LLM_BASE_URL=https://api.openai.com/v1
         export AGENT_FINDER_LLM_API_KEY=sk-...
         export AGENT_FINDER_LLM_MODEL=gpt-4o-mini

There is NO email-only authentication for raw LLM APIs -- that is why
the CLI slot above exists for session-based access instead.

Without AGENT_FINDER_LLM_API_KEY the hook is DORMANT: the pipeline is
fully deterministic and needs no LLM at all (that is a design feature --
evidence discipline, reproducibility). The LLM is only ever an ADVISER
in the gaps the deterministic engine cannot close:

  1. filling the TODOs of an auto-generated setup harness scaffold
     (the engine cannot know how to deploy an arbitrary protocol);
  2. sharpening REJECT retry hints for the refinement loop.

It NEVER upgrades evidence, never invents facts, and its output is
marked LLM-PROPOSED until an executable validator CONFIRM/REJECT says
otherwise.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


def backend() -> str:
    """Which transport is configured: 'cli' | 'api' | '' (dormant).

    'cli' takes precedence: AGENT_FINDER_LLM_CMD is a shell command that
    receives the full prompt on STDIN and must print the answer to
    STDOUT. That is the slot for session-based access -- e.g. when the
    ZCode desktop app ships a headless CLI driven by your existing
    email-login session, point this at it and the whole pipeline can
    consult the assistant with no API key at all:

        export AGENT_FINDER_LLM_CMD="zcode-headless --print"

    (Today the ZCode client is a desktop app with no callable headless
    mode, so this slot stays empty by default. It also fits any other
    CLI-authenticated model tool.)
    """
    if os.environ.get("AGENT_FINDER_LLM_CMD"):
        return "cli"
    if os.environ.get("AGENT_FINDER_LLM_API_KEY"):
        return "api"
    return ""


def available() -> bool:
    return backend() != ""


def status_line() -> str:
    mode = backend()
    if mode == "cli":
        cmd = os.environ.get("AGENT_FINDER_LLM_CMD", "")
        return (f"LLM hook: ACTIVE via CLI ({cmd}) -- adviser only, never "
                f"upgrades evidence")
    if mode == "api":
        model = os.environ.get("AGENT_FINDER_LLM_MODEL", "default-model")
        return f"LLM hook: ACTIVE ({model}) -- adviser only, never upgrades evidence"
    return ("LLM hook: DORMANT (set AGENT_FINDER_LLM_CMD for a session/"
            "CLI-based model, or AGENT_FINDER_LLM_API_KEY for an "
            "OpenAI-compatible endpoint; pipeline runs fully deterministic)")


def _chat(system: str, user: str, max_tokens: int = 2048) -> str:
    prompt = f"[system]\n{system}\n\n[user]\n{user}"
    if backend() == "cli":
        return _chat_cli(prompt)
    return _chat_api(system, user, max_tokens)


def _chat_cli(prompt: str) -> str:
    import subprocess
    cmd = os.environ["AGENT_FINDER_LLM_CMD"]
    proc = subprocess.run(cmd, shell=True, input=prompt,
                          capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(f"cli backend failed: {proc.stderr[:300]}")
    return proc.stdout


def _chat_api(system: str, user: str, max_tokens: int) -> str:
    base = os.environ.get("AGENT_FINDER_LLM_BASE_URL",
                          "https://api.openai.com/v1").rstrip("/")
    key = os.environ.get("AGENT_FINDER_LLM_API_KEY", "")
    model = os.environ.get("AGENT_FINDER_LLM_MODEL", "gpt-4o-mini")
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": 0,
        "max_tokens": max_tokens,
    }).encode()
    req = urllib.request.Request(
        f"{base}/chat/completions", data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read().decode())
    return body["choices"][0]["message"]["content"] or ""


def looks_like_solidity(text: str) -> bool:
    head = text.strip().lower()
    return ("pragma solidity" in head) and ("contract " in head)


def fill_harness_scaffold(scaffold_path: str) -> dict[str, Any]:
    """Ask the LLM to fill an auto-generated harness scaffold.

    Returns {filled: bool, reason: str, path: str}. The response is only
    written back when it looks like Solidity; otherwise the scaffold
    stays as-is for a human. The file keeps its header noting the LLM
    proposal must be reviewed.
    """
    if not available():
        return {"filled": False,
                "reason": "dormant (no API key)",
                "path": scaffold_path}
    try:
        with open(scaffold_path, encoding="utf-8") as f:
            scaffold = f.read()
        system = (
            "You fill Solidity test setup harnesses. You implement the "
            "IProtocolHarness shape exactly as scaffolded (same function "
            "signatures), replacing ONLY the TODO bodies. You deploy the "
            "REAL contracts from the repository under test (never rewrite "
            "them), use the Foundry cheatcode address "
            "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D for vm operations "
            "(declare your own minimal interface). Return ONLY Solidity "
            "source code, no commentary."
        )
        answer = _chat(system, scaffold)
        if not looks_like_solidity(answer):
            return {"filled": False, "reason": "response not Solidity",
                    "path": scaffold_path}
        header = ("// LLM-PROPOSED harness (AGENT_FINDER assistant). Review "
                  "before trusting; the validator still CONFIRM/REJECTs.\n")
        with open(scaffold_path, "w", encoding="utf-8") as f:
            f.write(header + answer + "\n")
        return {"filled": True, "reason": "scaffold filled (LLM-PROPOSED)",
                "path": scaffold_path}
    except Exception as exc:  # network, auth, format -- never fatal
        return {"filled": False, "reason": f"assistant error: {exc}",
                "path": scaffold_path}


def reject_refinement_hint(verdict: dict[str, Any]) -> str:
    """Sharpen a REJECT retry hint (advisory text only)."""
    if not available():
        return verdict.get("retry_hint", "")
    try:
        system = (
            "You refine security-pipeline retry hints. Given a REJECT "
            "verdict, propose the single most likely fix: harness setup "
            "error vs. real hypothesis flaw. One short paragraph."
        )
        user = json.dumps({k: verdict.get(k) for k in
                           ("attack_id", "verdict", "reason", "retry_hint")})
        return f"{verdict.get('retry_hint', '')} [LLM: {_chat(system, user, 512)}]"
    except Exception:
        return verdict.get("retry_hint", "")
