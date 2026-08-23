# MemoryGuard – Day 14

## Policy Enforcement, Risk Aggregation & Security Logging

### Date
21 August 2026

---

## 1. Day 14 Goal

The goal of Day 14 was to complete and integrate the security decision-making and security logging layer of MemoryGuard.

The system should be able to:

- Analyze incoming memory content.
- Aggregate security analysis results.
- calculate a final risk score.
- Apply a deterministic security policy.
- Allow low-risk memories.
- Send medium-risk memories for review.
- Block high-risk memories.
- Store security events for blocked memories.
- Verify the complete security flow using REST API and PostgreSQL.

---

# 2. Security Architecture

The security flow implemented during Day 14 is:

```text
Incoming Memory
       |
       v
Security Analyzer
       |
       v
Risk Aggregator
       |
       v
Final Risk Score
       |
       v
Policy Engine
       |
   +---+---+
   |   |   |
   v   v   v
  SAFE REVIEW BLOCK
   |   |   |
   v   v   v
 Save Save Security Log

---

## 3. Hardening & Pre-requisite Architecture Fixes

The following gaps identified in the Day 1–14 audit were fixed to harden the security boundary:

### 3.1 Quarantined (REVIEW) Memory Isolation
- **Problem**: Memories marked for `REVIEW` were returned by `/api/memories`, allowing the AI agent to retrieve unverified/quarantined data.
- **Fix**: Modified `GET /api/memories` to accept a query parameter `status` defaulting to `SAFE`. The AI agent's normal trusted-memory retrieval path now only fetches allowed memories. 
- **Console Audits**: The security console can retrieve review cases by calling `/api/memories?status=REVIEW` or `/api/memories?status=ALL`.

### 3.2 Backend-Driven Dashboard Statistics
- **Problem**: Blocked attempts were not persisted in the database, causing the frontend to report `0` blocked memories on the dashboard.
- **Fix**: Exposed a new `/api/memories/stats` GET endpoint in `MemoryController` that runs count queries using JPA (`countByStatus("SAFE")`, `countByStatus("REVIEW")`, and `countByActionTaken("BLOCKED")`). The frontend dashboard was updated to fetch from this statistics endpoint.

### 3.3 Safe Trace & Correlation Identifiers
- **Problem**: Blocked events had no reference to the triggering request or transaction, and saving the malicious payload in security logs creates a secondary data leakage risk.
- **Fix**: Added a `correlationId` UUID field to both `Memory` and `SecurityLog`. A random UUID is generated server-side during request initialization and propagated through the analysis and policy decision. If the input is blocked, the UUID is stored with the security log, enabling trace correlation without persisting sensitive content.

### 3.4 Java Version Mismatch
- **Verification**: Verified that the Maven build is executed using JDK 25 (via Maven wrapper), but compiles code targeting Java 21 compatibility as configured in the `pom.xml`. Documented this alignment in `DAY1.md`.

---

## 4. AI Semantic Layer — Stage 1 Setup

We have completed Stage 1 of the AI Semantic Security Layer implementation:

### 4.1 Configuration Mapping
- Added configuration properties in `application.properties` and `application-example.properties` under the prefix `memoryguard.ai`.
- The properties include:
  - `memoryguard.ai.enabled=false` (Disabled by default to ensure no runtime disruption until semantic checks are fully integrated).
  - `memoryguard.ai.provider=gemini` (Initial planned model provider).
  - `memoryguard.ai.model=gemini-2.5-flash`
  - `memoryguard.ai.api-key=${GEMINI_API_KEY:}` (Read from system environment variables to prevent credentials from being exposed in source code).
  - `memoryguard.ai.connect-timeout-ms=1000` (Enforces connection timeout).
  - `memoryguard.ai.read-timeout-ms=3000` (Enforces read timeout).
  - `memoryguard.ai.max-input-length=2000`

### 4.2 Start-up Validation
- Implemented `@PostConstruct` validation in `AiConfigProperties` ensuring that if `memoryguard.ai.enabled` is set to `true`, the application will fail to start if the API key is blank or missing.

### 4.3 Provider Isolation
- Defined a clean interface contract `AIService` which returns `SecurityAnalysisResult`.
- Created `GeminiAIService` implementing `AIService` to isolate Gemini-specific HTTP calls.
- Configured Spring's built-in `RestClient` request factory with the properties-bound timeout settings.
- The `evaluate()` method throws `UnsupportedOperationException` in Stage 1 but is fully implemented in Stage 2.

---

## 5. AI Semantic Layer — Stage 2 Gemini Integration

We have completed Stage 2 of the AI Semantic Security Layer implementation:

### 5.1 RestClient Post Integration & Header Authentication
- Implemented actual content generation POST requests inside `GeminiAIService` mapping to `/v1beta/models/{model}:generateContent`.
- All request and response structures are mapped cleanly to private DTO models (`GeminiRequest` and `GeminiResponse`) to prevent model-specific definitions from leaking to the rest of the security architecture.
- Authentication is handled securely via the **`x-goog-api-key` HTTP header**, removing the API key query parameter from request URLs.

### 5.2 Structured Output Enforcement
- Configured Gemini `responseSchema` and `responseMimeType: "application/json"` parameters in the request generation config, forcing the model to return a structured JSON response matching the model:
  ```json
  {
    "riskScore": 0-100,
    "riskLevel": "LOW" | "MEDIUM" | "HIGH",
    "threatCategory": "...",
    "confidence": 0.0-1.0,
    "reason": "..."
  }
  ```

### 5.3 Prompt Injection Defense & Boundaries
- User-provided memory content is clearly delimited using tag-based wrappers (`<UNTRUSTED_CONTENT> ... </UNTRUSTED_CONTENT>`).
- Enforced strict system instructions to force Gemini to act solely as a security classifier and ignore any execution commands located in the untrusted user block.

### 5.4 Server-Side Verification & Sanitized Exception Propagation
- Implemented comprehensive, server-side parameter checks validating that every field exists and complies with expectations (e.g. score and confidence bounds, valid risk level strings, and string size limitations) before constructing a `SecurityAnalysisResult`.
- Malformed inputs/blank values throw a controlled `AIServiceException` with appropriate `FailureType` (e.g., `MALFORMED_RESPONSE`, `INVALID_RESULT`, `INPUT_EXCEEDED`).
- Exceptions are fully sanitized: raw parser exceptions and HTTP request exception objects are **never** passed as causes to `AIServiceException` to prevent stack trace leaks of keys, prompts, or memory contents.

### 5.5 Privacy & Telemetry Protections
- Checked that the raw request content, system prompts, and api keys are never printed or written to system log files.
- Excluded raw exception details or api credentials from error messaging.

### 5.6 Mock API Unit Tests & Envelope Verification
- Expanded unit test cases inside `GeminiAIServiceTests` using Spring's `MockRestServiceServer` to verify correct behavior under diverse API scenarios (including valid risks levels, score/confidence range bounds violations, missing fields, timeouts, and network connection errors) without making external network calls.
- Added explicit test cases verifying header-based authentication, type mismatch failures (e.g. `riskScore` as string), missing candidate structures, empty parts, and empty text blocks, bringing the mock test coverage to **23 tests**.

---

## 6. AI Semantic Layer — Stage 3 Semantic Security Analyzer

We have successfully completed Stage 3 of the AI Semantic Security Layer:

### 6.1 Creating the AISemanticSecurityAnalyzer Bean
- Created the Spring bean `AISemanticSecurityAnalyzer` implementing the standard `SecurityAnalyzer` interface.
- Utilizes constructor injection to receive the `AIService` and `AiConfigProperties` beans, avoiding any direct dependencies on HTTP client modules or vendor-specific payloads.
- Kept the existing deterministic `MemoryRiskAnalyzer` annotated as `@Primary` to avoid conflicting autowire definitions or changing the active core evaluation path during Stage 3.

### 6.2 Default Disabled Behavior
- If `memoryguard.ai.enabled` is `false`, the semantic analyzer immediately returns a placeholder result indicating that the AI is unavailable (`riskScore = 0`, `confidence = 0.0`, `analyzerType = "SEMANTIC"`, `threatCategory = "SEMANTIC_UNAVAILABLE"`) without triggering any remote rest calls or throwing boot exceptions.

### 6.3 Secure Fail-Safe Fallbacks & Exception Sanitization
- Catches all `AIServiceException` occurrences (timeouts, connection faults, parsing/validation errors) and maps them to a generic, secure `SEMANTIC_UNAVAILABLE` fail-safe response.
- The fail-safe result excludes raw exception traces, request URLs, and input memory contents, guaranteeing that internal credentials or untrusted payloads are never exposed.

### 6.4 Unit and Integration Tests
- Created `AISemanticSecurityAnalyzerTests` covering 10 validation scenarios using a mock `AIService`:
  - HIGH, MEDIUM, and LOW risk response returns.
  - Fail-safe placeholders on timeouts, malformed candidate parses, and HTTP failures.
  - Custom null/blank content formatting.
  - Leak-prevention checks asserting that API keys (e.g. `"API_KEY_SECRET_123"`) or raw memory content are completely filtered and absent from error reasons.

---

## 7. AI Semantic Layer — Stage 4A Sequential Multi-Analyzer Integration

We have successfully completed Stage 4A of the AI Semantic Security Layer:

### 7.1 Multi-Analyzer Dependency Injection
- Refactored `MemoryService` to accept `List<SecurityAnalyzer>` in the constructor instead of a single analyzer bean. This automatically loads both `MemoryRiskAnalyzer` and `AISemanticSecurityAnalyzer` from the Spring application context.
- Removed the temporary `@Primary` annotation from `MemoryRiskAnalyzer`, allowing clean collection-injection without autowire ambiguity.

### 7.2 Sequential Analysis Execution
- Updated `MemoryService.analyzeRisk()` to sequentially execute each injected `SecurityAnalyzer` bean:
  ```java
  for (SecurityAnalyzer analyzer : securityAnalyzers) {
      SecurityAnalysisResult res = analyzer.analyze(memory.getContent());
      results.add(res);
  }
  ```
- Collects all resulting security signals and forwards them as a unified list to the `RiskAggregator` for combined assessment.

### 7.3 Safety-First Aggregation Strategy
- Updated `RiskAggregator.aggregate()` to evaluate both deterministic and semantic results under a safety-first maximum-score algorithm:
  - Iterates and filters out any `SEMANTIC_UNAVAILABLE` results, ensuring that a disabled or failed AI service does not corrupt or degrade deterministic block calculations.
  - If AI is disabled/unavailable, the deterministic rule result remains the final active result.
  - Resolves highest score selection, protecting deterministic blocks from downgrade overrides (e.g. Rule = 95 / AI = 5 evaluates to score 95).
  - Keeps policy decisions isolated inside `PolicyEngine`, which gating-evaluates only the aggregated outcome.

### 7.4 Mock Aggregation Unit Tests
- Created `MultiAnalyzerAggregationTests` covering 11 testing scenarios verifying:
  - Aggregation cases with deterministic-only and both-analyzer lists.
  - AI disabled and unavailable ignore-scenarios.
  - Safety-first score selection combinations (Rule LOW + AI HIGH, Rule HIGH + AI LOW, Rule MEDIUM + AI HIGH, etc.).
  - Non-downgrading security block assertions.

---

## 8. AI Semantic Layer — Stage 4B Bounded Parallel Analyzer Execution

We have successfully completed Stage 4B of the AI Semantic Security Layer:

### 8.1 Spring Managed Bounded Executor
- Introduced properties `memoryguard.security.analysis.parallelism` (default: 2) and `memoryguard.security.analysis.timeout-ms` (default: 1500) under [application.properties](file:///e:/software/MemeoryGuard/memoryguard-backend/src/main/resources/application.properties).
- Created a configuration bean `SecurityAnalysisExecutorConfig` managing a Spring-lifecycle bounded thread pool (`ThreadPoolExecutor` with worker count equal to configured parallelism and a task queue size limit of 1000) that shuts down gracefully via `destroyMethod = "shutdown"`.

### 8.2 Parallel Analyzer Submission & Isolation
- Updated `MemoryService.analyzeRisk()` to concurrently submit deterministic and semantic analysis tasks to the bounded executor.
- Enforces per-analyzer timeout isolation via `Future.get(timeout, TimeUnit.MILLISECONDS)`.
- If the AI semantic analyzer hangs, times out, or throws exceptions, it is cleanly isolated and mapped to the generic `SEMANTIC_UNAVAILABLE` fail-safe response.
- **Deterministic Baseline Protection**: Any timeout or crash of the deterministic analyzer propagates the exception, failing the memory save transaction rather than silently converting it into a false low-risk safe state.

### 8.3 Polymorphic Type Checking
- Added a `default String getAnalyzerType()` method to `SecurityAnalyzer` interface contract returning `"DETERMINISTIC"` by default.
- Overridden in `AISemanticSecurityAnalyzer` to return `"SEMANTIC"`. This permits clean, interface-driven differentiation of baseline and fallback task exceptions inside `MemoryService` without resorting to `instanceof` or class reflection checks.

### 8.4 Concurrency & Timeout Unit Tests
- Created `ConcurrencyTimeoutTests` containing 4 deterministic concurrency validation tests:
  - `testGenuinelyParallelExecution`: Uses coordinating `CountDownLatch` primitives to prove that both analyzers are entered and run concurrently.
  - `testAIAnalyzerTimeoutDoesNotDiscardDeterministicResult`: Proves a slow/hung AI analyzer is canceled after the timeout threshold while the rule result is successfully retained.
  - `testAIAnalyzerExceptionDoesNotDiscardDeterministicResult`: Proves an AI API key exception does not crash the baseline analysis transaction.
  - `testDeterministicAnalyzerFailurePropagated`: Asserts that a deterministic rules failure correctly propagates the exception and halts processing.

---

## 9. AI Semantic Layer — Stage 5A Security Observability & Safe Telemetry

We have successfully completed Stage 5A of the MemoryGuard project:

### 9.1 Database Telemetry Model
- Extended the `SecurityLog` entity with safe structured metadata fields:
  - `analyzerType` (`String(50)`): Tracks the type of the analyzer that produced the decision (`RULE` or `SEMANTIC`).
  - `riskLevel` (`String(20)`): Stores the evaluated risk category (`LOW`, `MEDIUM`, `HIGH`).
  - `confidence` (`Double`): Captures the model's confidence boundary factor.
- **Privacy Gating**: **MemoryGuard stores structured security metadata ONLY**. Raw memory payload contents, AI prompts, system prompts, Gemini API responses, and exception traces are excluded from telemetry persistence.

### 9.2 Unified Telemetry Pipeline
- Modified `MemoryService.createMemory()` to generate a `SecurityLog` for **every** pipeline outcome (ALLOW/SAFE, REVIEW, and BLOCK).
- Blocked requests retain `correlationId` tracking while mapping `memoryId = null`, preventing any database persistence of the blocked text payload.
- Unified result consistency by propagating the specific winning analyzer type (`RULE` or `SEMANTIC`) inside `RiskAggregator.aggregate()` rather than hardcoding a generic value.

### 9.3 Frontend Dashboard Integration
- Expanded `pages/SecurityLogs.jsx` table view with columns for **Source (Analyzer Type)**, **Risk Level**, and **Confidence**.
- Wrapped memory ID rendering to display `—` for blocked attempts instead of showing raw null values.

### 9.4 Telemetry Observability Tests
- Created `SecurityTelemetryTests` with 7 validation test cases verifying:
  - Telemetry generation for SAFE, REVIEW, and BLOCK decisions.
  - Correct `correlationId` association and null-safety when saving memory ID on block.
  - Explicitly tested that sensitive test strings (`"SECRET_MEMORY_PAYLOAD"`, `"API_KEY_SECRET_123"`, and `"RAW_GEMINI_RESPONSE"`) are not written to telemetry logs.

---

## 10. Software Supply-Chain Security (OWASP A03:2025)

We have explicitly mapped and documented the **OWASP A03:2025 Software Supply-Chain Failures** risk domain for the MemoryGuard platform:

### 10.1 Segregated Security Layers
The MemoryGuard architecture is defined across two distinct, non-overlapping security domains:
1. **Runtime Memory Security (Active)**: Coordinates parallel rules-based and semantic security analysis, risk score aggregation, policy actions, and structured telemetry logging to protect the AI agent's memory.
2. **Software Supply-Chain Security (Planned)**: Establishes build-time and compile-time controls for third-party libraries, compile toolchains, and package binaries that build and run the MemoryGuard application.

### 10.2 Threat Modeling (OWASP A03:2025 Relevance)
Recognized threat vectors affecting MemoryGuard dependencies include:
- Maliciously compromised Maven dependency packages.
- Outdated third-party components containing active CVE vulnerabilities.
- Vulnerabilities within Maven/JVM compiler toolchains.
- Outdated database drivers or HTTP connectors (e.g. within Spring Boot core stack).

**Attack Vector Diagram**:
```
Vulnerable / Malicious Dependency ──► MemoryGuard Backend ──► Security Boundary Compromised
```

### 10.3 Future Implementation Roadmap (Planned Milestone)
The following tasks are scheduled for a future dedicated **Supply-Chain Security** milestone (No runtime code changes have been introduced in this phase):
1. **SBOM Generation**: Set up Maven plugins (e.g., CycloneDX) to auto-generate a Software Bill of Materials.
2. **Dependency Vulnerability Scanning**: Integrate automated dependency-check tools in compilation/CI loops.
3. **CVE/OSV Intelligence Feed**: Cross-reference dependency versions against CVE/GitHub Advisory databases.
4. **Build Gating**: Configure CI policies to break builds or alert developers if dependencies exceed vulnerability score thresholds (e.g. CVSS >= 7.0).
5. **Automated Upgrades**: Implement dependency update automation to proactively keep library frameworks patched.






