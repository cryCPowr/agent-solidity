"""Attack Agent: transform Threat hypotheses into concrete attack paths.

Pipeline position (for_attack_agent.md):

    THREAT AGENT -> SECURITY MODEL -> ATTACK AGENT -> HYPOTHESIS QUEUE
                 -> VALIDATOR -> FINDING AGENT

This package is deliberately GENERIC: it reasons only over Recon fact
types/properties, Threat hypothesis structure, and source locations --
never over protocol, contract, function, or token names.
"""

from .model import AttackHypothesis
from .pipeline import generate_attacks

__all__ = ["AttackHypothesis", "generate_attacks"]
