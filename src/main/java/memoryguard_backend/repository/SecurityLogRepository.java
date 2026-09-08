package memoryguard_backend.repository;

import memoryguard_backend.entity.SecurityLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SecurityLogRepository 
        extends JpaRepository<SecurityLog, Long> {
    long countByActionTaken(String actionTaken);
    Optional<SecurityLog> findFirstByMemoryIdOrderByCreatedAtDesc(Long memoryId);
    Optional<SecurityLog> findFirstByCorrelationIdOrderByCreatedAtDesc(String correlationId);
}