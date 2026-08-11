package memoryguard_backend.repository;

import memoryguard_backend.entity.SecurityLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityLogRepository 
        extends JpaRepository<SecurityLog, Long> {

}