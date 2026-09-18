package memoryguard_backend.repository;

import memoryguard_backend.entity.PolicyVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PolicyVersionRepository extends JpaRepository<PolicyVersion, Long> {
    
    Optional<PolicyVersion> findTopByStatusOrderByIdDesc(String status);

    Optional<PolicyVersion> findTopByOrderByVersionDesc();

    Optional<PolicyVersion> findByVersion(Integer version);

    List<PolicyVersion> findAllByOrderByVersionAsc();

    List<PolicyVersion> findByStatus(String status);
}
