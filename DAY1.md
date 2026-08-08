# MemoryGuard — Day 1

## Project

MemoryGuard – AI Agent Security Platform

## Day 1 Objective

Set up the initial development environment and prepare the backend project foundation for MemoryGuard.

---

## 1. Project Structure

Project workspace was created under:


E:\software\MemeoryGuard

Backend project:

E:\software\MemeoryGuard\memoryguard-backend

The Spring Boot backend was generated using Spring Initializr.

---

## 2. Spring Boot Project Setup

A Spring Boot backend project was created with:

- Project: Maven
- Language: Java
- Packaging: JAR
- Java: 25 LTS
- Spring Boot: 4.1.0
- Project name: memoryguard-backend
- Package: memoryguard_backend

Main application class:

MemoryguardBackendApplication.java

---

## 3. Java Environment

Java installation was verified successfully.

Java version:

25.0.2 LTS

Java runtime:

Oracle JDK 25.0.2

---

## 4. Maven Setup

Maven Wrapper provided by Spring Initializr was verified.

Command used:

.\mvnw.cmd -version

Maven version:

3.9.16

The Maven Wrapper allows the project to use the configured Maven version without requiring a separate global Maven installation.

---

## 5. Backend Build Verification

The project was built using:

.\mvnw.cmd clean package

The initial build encountered a Windows permission issue while creating:

target\classes

The project directory permissions were corrected and the Maven build was successfully completed.

---

## 6. PostgreSQL Setup

PostgreSQL was configured for MemoryGuard.

Database created:

memoryguard

Database server:

PostgreSQL 17

The backend was configured to connect to:

jdbc:postgresql://localhost:5432/memoryguard

---

## 7. Project Dependencies

The backend was prepared with the required Spring Boot dependencies for:

- Spring Web
- Spring Data JPA
- PostgreSQL
- Spring Security
- Spring Boot DevTools
- Testing

These dependencies provide the foundation for:

REST APIs
Database persistence
Security
Development workflow
Testing

---

## 8. Initial Backend Configuration

The application was configured to use PostgreSQL as its database.

JPA/Hibernate was configured for database persistence.

The backend was initially configured to run on port 8080.

Because port 8080 was already occupied by another Windows process, the application port was changed to:

8081

Final backend URL:

http://localhost:8081

---

## 9. Development Environment

Tools used:

- VS Code
- Java JDK 25
- Maven Wrapper
- Spring Boot
- PostgreSQL
- pgAdmin
- Git

---

## 10. Initial Verification

The following were successfully verified:

- Java installation
- Maven Wrapper
- Spring Boot project structure
- PostgreSQL installation
- MemoryGuard database
- Backend-to-database connectivity
- Spring Boot application startup

---

## Day 1 Outcome

The development environment and backend foundation for MemoryGuard were successfully prepared.

The project was ready for backend API and database development.

---

## Day 2 Starting Point

Day 2 began with:

- REST API development
- Spring Security configuration
- Memory entity design
- Repository layer
- Controller layer
- PostgreSQL CRUD operations