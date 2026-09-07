package memoryguard_backend.repository;

import memoryguard_backend.entity.QuarantinedMemory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface QuarantinedMemoryRepository extends JpaRepository<QuarantinedMemory, Long> {
    List<QuarantinedMemory> findByQuarantineStatus(String quarantineStatus);
    long countByQuarantineStatus(String quarantineStatus);
    Optional<QuarantinedMemory> findByCorrelationId(String correlationId);
}
