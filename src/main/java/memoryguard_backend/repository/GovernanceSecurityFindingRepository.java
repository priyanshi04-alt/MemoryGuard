package memoryguard_backend.repository;

import memoryguard_backend.entity.GovernanceSecurityFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface GovernanceSecurityFindingRepository extends JpaRepository<GovernanceSecurityFinding, Long> {

    Optional<GovernanceSecurityFinding> findByFindingId(String findingId);

    List<GovernanceSecurityFinding> findByStatus(String status);

    List<GovernanceSecurityFinding> findBySeverity(String severity);

    List<GovernanceSecurityFinding> findByAnomalyType(String anomalyType);

    List<GovernanceSecurityFinding> findAllByOrderByDetectedAtDesc();
}
