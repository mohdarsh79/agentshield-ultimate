# ADR-003: Fail-Closed Cryptographically Bound Human Approval Engine

## Status
Accepted

## Context
High-impact agent operations (e.g., executing money transfers, purchasing goods, sending external communications, deleting production databases, installing global software packages) must never be executed without explicit human consent.

## Decision
We implement a cryptographically bound Human Approval Engine:
1. High-risk actions generate an approval token bound to the SHA-256 hash of the exact operation parameters.
2. The approval request enforces a strict Time-to-Live (TTL).
3. If an approval fails, times out, or encounters an internal engine error, the system fails closed (blocks the action).

## Consequences
- **Positive**: Prevents unauthorized financial loss, data deletion, or supply-chain poisoning.
- **Negative**: Requires human operator presence for designated high-risk action tiers.
