package memoryguard_backend.service;

import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.repository.SecurityLogRepository;

import org.springframework.stereotype.Service;


@Service
public class SecurityLogService {


    private final SecurityLogRepository repository;


    public SecurityLogService(SecurityLogRepository repository){
        this.repository = repository;
    }


    public SecurityLog save(SecurityLog log){

        return repository.save(log);

    }

}