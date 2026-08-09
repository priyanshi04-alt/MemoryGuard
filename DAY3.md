# MemoryGuard - Day 3

## Memory Integrity Verification & Tamper Detection

---

## Objective

The objective of Day 3 was to implement a security layer for AI Agent memory storage by introducing cryptographic integrity verification.

The system should be able to:

- Generate a secure hash for every stored memory.
- Detect unauthorized modifications.
- Verify whether stored memories are intact or tampered.

---

# 1. Problem Statement

AI agents store important user information as memories.

Example:

```
User prefers Java explanations
```

If an attacker modifies this stored memory:

```
User prefers Java explanations
        |
        v
User prefers Python explanations
```

The system should detect this unauthorized change.

To solve this problem, MemoryGuard uses SHA-256 based integrity verification.

---

# 2. Memory Integrity Architecture


```
                Client
                  |
                  |
                  v
          POST /api/memories
                  |
                  |
                  v
        MemoryController
                  |
                  |
                  v
          MemoryService
                  |
                  |
          Generate SHA-256 Hash
                  |
                  |
                  v
             HashUtil
                  |
                  |
                  v
            PostgreSQL Database


Database stores:

Memory Content
+
Integrity Hash

```

---

# 3. SHA-256 Hash Generation

A cryptographic hash is generated for every memory using SHA-256.

Example:

Input:

```
MemoryGuard integrity test
```

Generated Hash:

```
f7e406bf3605e3c1d08ca8a032a883f28e1560e430f25b0cf6bee86a6b17e30e
```

Properties:

- Fixed length: 256 bits
- Output format: 64 hexadecimal characters
- One-way cryptographic function
- Small data changes produce completely different hashes

---

# 4. Hash Utility Implementation

Created:

```
src/main/java/memoryguard_backend/security/HashUtil.java
```

Responsibilities:

- Generate SHA-256 hash.
- Convert byte output into hexadecimal format.
- Return a secure integrity value.

Implementation uses:

```
java.security.MessageDigest
```

---

# 5. Database Schema Update

Added new column:

```sql
integrity_hash VARCHAR(64)
```

Purpose:

- Store SHA-256 digest of memory content.
- Maintain memory authenticity.
- Detect unauthorized database changes.


Existing database records were migrated by generating their corresponding hashes.

Example:

```
id: 1

content:
User prefers Java explanations

integrity_hash:
3be64e242de731206d93faca602afb0db4f6cb0d4e81bd41cf355cc874fbf730
```

---

# 6. Automatic Hash Generation During Memory Creation

Updated:

```
MemoryService.java
```

Flow:

1. Client sends memory data.

Example:

```json
{
 "agentId":3,
 "content":"MemoryGuard integrity test",
 "memoryType":"TEST"
}
```

2. Server extracts content.

3. SHA-256 hash is generated.

4. Hash is stored with memory.

5. Memory is saved into PostgreSQL.


Important:

The client never provides the integrity hash.

The server generates it internally to prevent manipulation.

---

# 7. Integrity Verification API

Created endpoint:

```
GET /api/memories/{id}/verify
```

Purpose:

Verify whether a memory has been modified after creation.

---

## Verification Process


```
Stored Memory
       |
       |
       v
Read Content From Database
       |
       |
       v
Generate New SHA-256 Hash
       |
       |
       v
Compare With Stored Hash
       |
       |
       +----------------+
       |                |
       v                v

   MATCH          DIFFERENT

   INTACT         TAMPERED

```

---

# 8. API Response

## INTACT Response

When memory content matches the stored hash:


```json
{
 "memoryId":4,
 "status":"INTACT",
 "message":"Memory integrity verified successfully"
}
```

Meaning:

- Data was not modified.
- Memory is trustworthy.

---

## TAMPERED Response

When memory content is modified:


```json
{
 "memoryId":4,
 "status":"TAMPERED",
 "message":"Memory integrity verification failed"
}
```

Meaning:

- Stored content was changed.
- Integrity violation detected.

---

# 9. Security Configuration Updates

Updated:

```
SecurityConfig.java
```

Allowed public access for:

```
GET /api/health

GET /api/memories

POST /api/memories

GET /api/memories/{id}/verify
```

Also allowed:

```
/error
```

to prevent Spring Security from masking backend exceptions as HTTP 403 errors.

---

# 10. Testing & Verification


## Test Case 1: Intact Memory Verification


Created memory:

```
MemoryGuard integrity test
```

Generated Hash:

```
f7e406bf3605e3c1d08ca8a032a883f28e1560e430f25b0cf6bee86a6b17e30e
```


Verification API:

```
GET /api/memories/4/verify
```


Result:

```
HTTP 200 OK
```

Response:

```json
{
 "memoryId":4,
 "status":"INTACT",
 "message":"Memory integrity verified successfully"
}
```

---

## Test Case 2: Tampered Memory Detection


Database content was manually modified:

Before:

```
MemoryGuard integrity test
```


After:

```
MemoryGuard integrity test - TAMPERED
```


Stored hash remained unchanged.


Verification Result:

```
HTTP 200 OK
```


Response:

```json
{
 "memoryId":4,
 "status":"TAMPERED",
 "message":"Memory integrity verification failed"
}
```

The system successfully detected unauthorized modification.

---

# 11. Build Verification


Command:

```bash
./mvnw clean package
```


Result:

```
BUILD SUCCESS
```

Test Results:

```
Tests run: 1
Failures: 0
Errors: 0
```

---

# 12. API Verification


| Endpoint | Status |
|---|---|
| GET /api/health | ✅ Working |
| GET /api/memories | ✅ Working |
| POST /api/memories | ✅ Working |
| GET /api/memories/{id}/verify | ✅ Working |

---

# 13. Files Added


New Files:

```
src/main/java/memoryguard_backend/security/HashUtil.java

src/main/java/memoryguard_backend/service/MemoryService.java
```

---

# 14. Files Modified


Modified:

```
src/main/java/memoryguard_backend/entity/Memory.java

src/main/java/memoryguard_backend/controller/MemoryController.java

src/main/java/memoryguard_backend/SecurityConfig.java
```

---

# 15. Git Commit


Commit:

```
feat: add memory integrity verification
```


Changes pushed successfully to GitHub.

---

# Day 3 Summary


MemoryGuard now supports:

✅ Cryptographic memory hashing  
✅ SHA-256 integrity protection  
✅ Automatic server-side hash generation  
✅ Memory verification API  
✅ Tamper detection mechanism  
✅ Secure database integrity tracking  


## Day 3 Status

COMPLETED ✅

MemoryGuard has successfully evolved from a memory storage system into a secure AI Agent memory protection platform.