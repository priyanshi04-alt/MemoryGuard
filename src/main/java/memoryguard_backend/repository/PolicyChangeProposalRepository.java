package memoryguard_backend.repository;

import memoryguard_backend.entity.PolicyChangeProposal;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PolicyChangeProposalRepository extends JpaRepository<PolicyChangeProposal, Long> {

    Optional<PolicyChangeProposal> findByProposalId(String proposalId);

    List<PolicyChangeProposal> findAllByOrderByCreatedAtDesc();

    List<PolicyChangeProposal> findByStatus(String status);
}
