# MemoryGuard — AI Agent Memory Security Platform

MemoryGuard is a security gateway and monitoring platform designed to secure the memory storage layer of AI agents. It applies both deterministic security rules and semantic AI-based threat classification to analyze memory content before ALLOWING, REVIEWING, or BLOCKING memory writes.

---

## Architecture Overview

The system consists of two distinct security domains:

### A. Runtime Memory Security (Active)

Analyzes and regulates incoming memory content written by AI agents:

```
Memory Gateway
   │
   ├──► Rule Analyzer (MemoryRiskAnalyzer)
   └──► AI Semantic Analyzer (AISemanticSecurityAnalyzer)
         │
         ▼ (Parallel Bounded Execution)
   Risk Aggregator (Safety-First Max Combination)
         │
         ▼ (Aggregated Result)
   Policy Engine
         │
         ▼
[ ALLOW / REVIEW / BLOCK ] ──► Security Logging & Telemetry
```

### B. Software Supply-Chain Security (Planned Future Layer)

Regulates and validates third-party libraries, build tools, and package binaries that build and run the MemoryGuard application. This layer mitigates supply-chain threats (OWASP A03:2025).

```
Maven Dependencies
   │
   ▼
SBOM Generation
   │
   ▼
Vulnerability Scanning (CVE / OSV)
   │
   ▼
Risk Assessment & Policy Enforcement
   │
   ▼
Patch / Update
```

---

## Software Supply-Chain Security (OWASP A03:2025)

MemoryGuard depends on external frameworks and third-party Maven libraries (such as Spring Boot, Jackson, HTTP connectors, and Gemini API client libraries). These components form part of the application's build and runtime attack surface.

### Threat Model (OWASP A03:2025 Relevance)
We recognize **Software Supply-Chain Security (OWASP A03:2025)** as a separate security layer distinct from runtime memory inspection. Potential threats in this layer include:
* Transitive dependencies with active CVEs (Common Vulnerabilities and Exposures).
* Maliciously compromised package versions or libraries published to public Maven repositories.
* Vulnerabilities inside compiler toolchains or Maven build plugins.
* Outdated third-party libraries hosting remote execution or validation bypass flaws.

**Attack Vector Diagram**:
```
Vulnerable / Malicious Dependency ──► MemoryGuard Backend ──► Security Boundary Compromised
```

### Future Implementation Roadmap
To proactively manage this domain, the following tasks are scheduled for a future dedicated **Supply-Chain Security** milestone (Not currently active or implemented in production code):
1. **SBOM Generation**: Set up automated generation of a Software Bill of Materials (SBOM) listing all Maven dependencies at build time.
2. **Dependency Composition Analysis**: Integrate automated vulnerability scanners into compiler/CI lifecycles.
3. **OSV/CVE Database Matching**: Connect toolchains to open-source advisory databases (such as OSV or GitHub Advisory Database).
4. **Vulnerability Gating Policies**: Configure build scripts to break or issue critical warnings if dependencies exceed defined security limits (e.g., CVSS >= 7.0).
5. **Continuous Patch Maintenance**: Implement automated library update configurations.
