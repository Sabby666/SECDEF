# Shared Contracts Package

Pure data contracts, shared DTOs, event schemas, and enums for Attack Surface Monitor.

## Boundary Rules

- **ALLOWED:** Pydantic DTOs, event schemas (`schema_version: "1.0"`), shared enums, serialization contracts.
- **FORBIDDEN:** Business logic, database ORM models, repositories, API controllers, authentication logic, scanner socket code.
- **DEPENDENCIES:** Dependency-light (Python standard library + Pydantic only).
