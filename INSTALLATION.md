# Installation & Setup Guide

## Requirements
- Node.js >= 18.0.0
- npm >= 9.0.0 (or pnpm / yarn)

## Global CLI Installation
```bash
npm install -g agentshield-ultimate
```

## Local Project Dependency
```bash
npm install --save agentshield-ultimate
```

## Running without Installation
```bash
npx agentshield-ultimate scan
```

## Initializing in an AI Agent Project
Run the initialization command inside your project root:
```bash
agentshield init
```
This generates `.agentshield/config.json` with strict zero-trust defaults.
