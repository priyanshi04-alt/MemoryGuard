package memoryguard_backend.repository;

import memoryguard_backend.entity.DeniedMemoryRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DeniedMemoryRepository extends JpaRepository<DeniedMemoryRecord, Long> {
    Optional<DeniedMemoryRecord> findByCorrelationId(String correlationId);
}
