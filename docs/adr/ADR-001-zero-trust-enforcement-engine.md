# ADR-001: Zero-Trust Runtime Enforcement Engine

## Status
Accepted

## Context
AI agents are guided primarily by natural language instructions. However, language models are fundamentally non-deterministic and can be deceived via direct prompt injection, indirect prompt injection (from web content, documents, tool outputs), or jailbreak attacks. Relying solely on prompts or model alignment to enforce security boundaries is inherently insecure.

## Decision
We implement an independent, deterministic Security Enforcement Engine in TypeScript that executes outside the model's cognitive loop. All agent interactions—including file operations, network requests, command execution, and browser actions—must be evaluated and authorized by this engine before execution.

## Consequences
- **Positive**: Complete defense against prompt injection compromising operating system or filesystem boundaries. Even if the LLM is fully subverted, unauthorized actions are blocked deterministically.
- **Negative**: Adds a minor pre-execution latency (< 5ms) for policy evaluation.
