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
    public ResponseEntity<EvaluationReport> runEvaluation(
            @RequestParam(value = "mode", required = false, defaultValue = "RULES_PLUS_AI") String mode) {
        EvaluationMode evalMode = EvaluationMode.fromString(mode);
        EvaluationReport report = evaluationService.runEvaluation(evalMode);
        return ResponseEntity.ok(report);
    }

    @PostMapping("/benchmark")
    public ResponseEntity<EvaluationReport> runBenchmark(
            @RequestParam(value = "mode", required = false, defaultValue = "COMPARATIVE") String mode) {
        EvaluationMode evalMode = EvaluationMode.fromString(mode);
        EvaluationReport report = evaluationService.runEvaluation(evalMode);
        return ResponseEntity.ok(report);
    }

    @PostMapping("/adversarial")
    public ResponseEntity<EvaluationReport> runAdversarialEvaluation() {
        EvaluationReport report = evaluationService.runEvaluation(EvaluationMode.RULES_PLUS_AI);
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
