# MemoryGuard — Day 2

## Objective

Build the backend foundation of MemoryGuard using Spring Boot,
PostgreSQL, JPA/Hibernate, Spring Security, and REST APIs.

---

## 1. Backend Setup

- Spring Boot backend created using Spring Initializr.
- Java 25 LTS configured.
- Maven Wrapper verified.
- Application runs on port 8081.

---

## 2. Database

PostgreSQL database:

memoryguard

Database connection verified successfully.

JPA/Hibernate successfully connected to PostgreSQL.

---

## 3. Spring Security

Created:

SecurityConfig.java

Current security behavior:

- `/api/health` → public
- `/api/memories` → temporarily public for development/testing
- Other endpoints → authentication required

CSRF is temporarily disabled for REST API development/testing.

---

## 4. Health Check API

Endpoint:

GET /api/health

Response:

MemoryGuard is running

Purpose:

Verify that the Spring Boot backend is running correctly.

---

## 5. Memory Entity

Created:

Memory.java

Fields:

- id
- agentId
- content
- memoryType
- createdAt
- updatedAt

JPA annotations used:

- @Entity
- @Table
- @Id
- @GeneratedValue
- @Column
- @PrePersist
- @PreUpdate

---

## 6. Repository Layer

Created:

MemoryRepository.java

Extends:

JpaRepository<Memory, Long>

Provides basic database operations such as:

- save()
- findAll()
- findById()
- deleteById()
- existsById()

---

## 7. Controller Layer

Created:

MemoryController.java

Base endpoint:

/api/memories

Implemented:

GET /api/memories

POST /api/memories

---

## 8. Testing

### GET memories

Request:

GET /api/memories

Initial response:

[]

This confirmed that the API could successfully communicate with
the database.

---

### POST memory

Request:

POST /api/memories

Example request:

{
  "agentId": 1,
  "content": "User prefers Java explanations",
  "memoryType": "PREFERENCE"
}

Successful response:

{
  "id": 1,
  "agentId": 1,
  "content": "User prefers Java explanations",
  "memoryType": "PREFERENCE",
  "createdAt": "...",
  "updatedAt": "..."
}

---

### GET verification

GET /api/memories successfully returned the stored memory.

This verified the complete flow:

Client
→ REST Controller
→ Repository
→ JPA/Hibernate
→ PostgreSQL

---

## Day 2 Outcome

The MemoryGuard backend foundation is working successfully.

The system can currently:

1. Start the Spring Boot backend.
2. Connect to PostgreSQL.
3. Expose REST APIs.
4. Create memories.
5. Retrieve memories.
6. Store memory data using JPA/Hibernate.
7. Apply basic Spring Security rules.

---

## Next — Day 3

Implement the MemoryGuard security layer:

- Service layer
- Memory integrity hashing
- SHA-256 hash generation
- Tamper detection
- Security/risk logic