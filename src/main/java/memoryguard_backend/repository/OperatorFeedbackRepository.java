package memoryguard_backend.repository;

import memoryguard_backend.entity.OperatorFeedback;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OperatorFeedbackRepository extends JpaRepository<OperatorFeedback, Long> {

    Optional<OperatorFeedback> findByFeedbackId(String feedbackId);

    List<OperatorFeedback> findByMemoryIdOrderByTimestampAsc(Long memoryId);

    List<OperatorFeedback> findByCorrelationIdOrderByTimestampAsc(String correlationId);

    List<OperatorFeedback> findByOperatorIdOrderByTimestampDesc(String operatorId);

    List<OperatorFeedback> findByFeedbackDecision(String feedbackDecision);

    boolean existsByMemoryId(Long memoryId);

    boolean existsByMemoryIdAndOperatorIdAndFeedbackDecision(Long memoryId, String operatorId, String feedbackDecision);

    List<OperatorFeedback> findAllByOrderByIdAsc();
}
