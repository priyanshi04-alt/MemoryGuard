package memoryguard_backend.repository;

import memoryguard_backend.entity.SecurityAuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SecurityAuditRepository extends JpaRepository<SecurityAuditEvent, Long> {

    Optional<SecurityAuditEvent> findByEventId(String eventId);

    List<SecurityAuditEvent> findByCorrelationIdOrderByTimestampAsc(String correlationId);

    List<SecurityAuditEvent> findByMemoryIdOrderByTimestampAsc(Long memoryId);

    List<SecurityAuditEvent> findByQuarantineIdOrderByTimestampAsc(Long quarantineId);

    Optional<SecurityAuditEvent> findTopByOrderByIdDesc();

    List<SecurityAuditEvent> findAllByOrderByIdAsc();
}
