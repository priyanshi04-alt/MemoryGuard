package memoryguard_backend.controller;

import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.repository.SecurityLogRepository;

import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/security-logs")
public class SecurityLogController {

    private final SecurityLogRepository securityLogRepository;

    public SecurityLogController(SecurityLogRepository securityLogRepository) {
        this.securityLogRepository = securityLogRepository;
    }

    @GetMapping
    public List<SecurityLog> getAllSecurityLogs() {
        return securityLogRepository.findAll();
    }
}