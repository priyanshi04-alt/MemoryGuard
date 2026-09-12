package memoryguard_backend.evaluation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/security/evaluation")
@CrossOrigin(origins = "*")
public class EvaluationController {

    private final SecurityEvaluationService evaluationService;

    @Autowired
    public EvaluationController(SecurityEvaluationService evaluationService) {
        this.evaluationService = evaluationService;
    }

    @PostMapping("/run")
    public ResponseEntity<EvaluationReport> runEvaluation() {
        EvaluationReport report = evaluationService.runEvaluation();
        return ResponseEntity.ok(report);
    }

    @PostMapping("/adversarial")
    public ResponseEntity<EvaluationReport> runAdversarialEvaluation() {
        EvaluationReport report = evaluationService.runEvaluation();
        return ResponseEntity.ok(report);
    }

    @GetMapping("/latest")
    public ResponseEntity<EvaluationReport> getLatestReport() {
        EvaluationReport report = evaluationService.getLatestReport();
        return ResponseEntity.ok(report);
    }

    @GetMapping("/adversarial")
    public ResponseEntity<EvaluationReport> getAdversarialReport() {
        EvaluationReport report = evaluationService.getLatestReport();
        return ResponseEntity.ok(report);
    }
}
