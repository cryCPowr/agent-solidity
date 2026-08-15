"""Model abstraction layer.

Provides a unified interface for invoking language models to assist with
semantic interpretation, hypothesis generation, and prioritization. The
deterministic graph/rule reasoning is the primary path; this layer only
enriches the result with semantic context.

Hardening constraints:
- LLM output must be grounded on Recon evidence
- Raw LLM prose is NEVER authoritative fact
- Every LLM-derived claim must reference Recon fact IDs
- If the LLM is unavailable, the deterministic path still works
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModelResponse:
    """Response from a language model invocation.

    The `grounded_fact_ids` field is mandatory: every claim made by the
    model must reference specific Recon fact IDs. Claims without grounding
    are dropped.
    """

    text: str
    grounded_fact_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    model_id: str = ""


class ModelProvider(ABC):
    """Abstract base for language model providers.

    Concrete implementations might wrap OpenAI, Anthropic, a local model,
    Hermes, or a no-op fallback. Threat Agent never depends on any
    specific provider.
    """

    @abstractmethod
    def generate(self, prompt: str, **kwargs: Any) -> ModelResponse:
        """Free-form generation."""

    @abstractmethod
    def structured_generate(
        self,
        prompt: str,
        schema: dict[str, Any],
        **kwargs: Any,
    ) -> ModelResponse:
        """Generate output matching a structured schema."""


class NoOpModelProvider(ModelProvider):
    """Deterministic fallback when no LLM is configured.

    Always returns an empty response. Threat Agent's deterministic
    reasoning still produces a complete result.
    """

    def generate(self, prompt: str, **kwargs: Any) -> ModelResponse:
        return ModelResponse(text="", grounded_fact_ids=[], model_id="noop")

    def structured_generate(
        self, prompt: str, schema: dict[str, Any], **kwargs: Any,
    ) -> ModelResponse:
        return ModelResponse(text="", grounded_fact_ids=[], model_id="noop")


def filter_grounded_claims(
    response: ModelResponse,
    known_fact_ids: set[str],
) -> ModelResponse:
    """Drop any LLM claims that do not reference known Recon fact IDs.

    This is the safety boundary: raw LLM prose without evidence becomes
    invisible to Threat Agent.
    """
    valid = [fid for fid in response.grounded_fact_ids if fid in known_fact_ids]
    return ModelResponse(
        text=response.text if valid else "",
        grounded_fact_ids=valid,
        metadata=response.metadata,
        model_id=response.model_id,
    )