# Scanner Worker Application

Isolated Network Discovery Worker for Attack Surface Monitor.

## Architectural Boundaries

- **NO DATABASE ACCESS:** Scanner workers have ZERO credentials to PostgreSQL or control plane databases.
- **NO AUTH/RISK LOGIC:** Workers DO NOT compute business severity or organizational risk scores.
- **DUAL-LAYER SAFETY:** Enforces Target Authorization check & Network Destination Safety (blocking private IPs, loopback, and `169.254.169.254`).
- **COMMUNICATION:** Dequeues jobs from Redis, executes discovery in container sandbox, returns signed JSON payload to Redis result queue.
