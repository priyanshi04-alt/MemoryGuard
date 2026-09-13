package memoryguard_backend.controller;

import memoryguard_backend.dto.CalibrationResponse;
import memoryguard_backend.dto.OperatorFeedbackRequest;
import memoryguard_backend.dto.OperatorFeedbackTelemetry;
import memoryguard_backend.entity.OperatorFeedback;
import memoryguard_backend.service.OperatorFeedbackService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/security/feedback")
public class OperatorFeedbackController {

    private final OperatorFeedbackService feedbackService;

    @Autowired
    public OperatorFeedbackController(OperatorFeedbackService feedbackService) {
        this.feedbackService = feedbackService;
    }

    @PostMapping
    public ResponseEntity<?> submitFeedback(
            @RequestHeader(value = "X-Operator-Id", required = false) String headerOperatorId,
            @RequestBody(required = false) OperatorFeedbackRequest request) {

        String operatorId = headerOperatorId != null && !headerOperatorId.trim().isEmpty()
                ? headerOperatorId.trim()
                : (request != null ? request.getOperatorId() : null);

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            OperatorFeedback feedback = feedbackService.submitFeedback(request, operatorId);
            return ResponseEntity.status(HttpStatus.CREATED).body(feedback);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("BAD_REQUEST", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ErrorResponse("CONFLICT", e.getMessage()));
        }
    }

    @GetMapping("/telemetry")
    public ResponseEntity<?> getTelemetry(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            OperatorFeedbackTelemetry telemetry = feedbackService.getTelemetry(operatorId);
            return ResponseEntity.ok(telemetry);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/calibration")
    public ResponseEntity<?> getCalibrationRecommendations(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            CalibrationResponse calibration = feedbackService.getCalibrationRecommendations(operatorId);
            return ResponseEntity.ok(calibration);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/{memoryId}")
    public ResponseEntity<?> getFeedbackByMemoryId(
            @PathVariable Long memoryId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            List<OperatorFeedback> feedbackList = feedbackService.getFeedbackByMemoryId(memoryId, operatorId);
            if (feedbackList.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ErrorResponse("NOT_FOUND", "No operator feedback found for memory ID: " + memoryId));
            }
            return ResponseEntity.ok(feedbackList);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("BAD_REQUEST", e.getMessage()));
        }
    }

    private ResponseEntity<?> validateOperatorAuthorization(String operatorId) {
        if (operatorId == null || operatorId.trim().isEmpty() || "ANONYMOUS".equalsIgnoreCase(operatorId.trim())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", "Authorization required: valid operator identity (X-Operator-Id) must be provided."));
        }
        return null;
    }

    public record ErrorResponse(String errorCode, String message) {}
}
