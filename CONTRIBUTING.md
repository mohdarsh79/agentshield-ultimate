# Contributing to AgentShield Ultimate

Thank you for your interest in contributing to AgentShield Ultimate!

## Development Setup

1. Fork and clone the repository.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the build:
   ```bash
   npm run build
   ```
4. Run all tests:
   ```bash
   npm test
   ```

## Pull Request Guidelines

1. Ensure all TypeScript types pass without errors (`npm run typecheck`).
2. Add automated regression tests for any new guard, policy, or vulnerability remediation.
3. Keep changes scoped, well-documented, and atomic.
4. Follow conventional commit message formatting.

## Security Disclosures

For security vulnerabilities, please refer to [SECURITY.md](SECURITY.md) and report privately rather than opening public GitHub issues.
