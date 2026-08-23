package memoryguard_backend.repository;

import memoryguard_backend.entity.Memory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface MemoryRepository extends JpaRepository<Memory, Long> {
    List<Memory> findByStatus(String status);
    long countByStatus(String status);
}