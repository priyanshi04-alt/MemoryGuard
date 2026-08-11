package memoryguard_backend.service;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.SecurityLog;

import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.security.HashUtil;
import memoryguard_backend.security.MemoryRiskAnalyzer;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


@Service
public class MemoryService {


    private final MemoryRepository memoryRepository;
    private final MemoryRiskAnalyzer memoryRiskAnalyzer;
    private final SecurityLogService securityLogService;


    public MemoryService(
            MemoryRepository memoryRepository,
            MemoryRiskAnalyzer memoryRiskAnalyzer,
            SecurityLogService securityLogService) {

        this.memoryRepository = memoryRepository;
        this.memoryRiskAnalyzer = memoryRiskAnalyzer;
        this.securityLogService = securityLogService;
    }



    public List<Memory> getAllMemories() {

        List<Memory> memories = memoryRepository.findAll();

        for(Memory memory : memories){
            analyzeRisk(memory);
        }

        return memories;
    }



    public Optional<Memory> getMemoryById(Long id){

        Optional<Memory> memory = memoryRepository.findById(id);

        if(memory.isPresent()){
            analyzeRisk(memory.get());
        }

        return memory;
    }




    public boolean verifyIntegrity(Memory memory){

        String calculatedHash =
                HashUtil.generateHash(memory.getContent());

        return calculatedHash.equals(memory.getIntegrityHash());
    }





    public Memory createMemory(Memory memory){


        String hash =
                HashUtil.generateHash(memory.getContent());


        memory.setIntegrityHash(hash);



        Memory savedMemory =
                memoryRepository.save(memory);



        analyzeRisk(savedMemory);



        if(savedMemory.getRiskScore() >= 80){


            savedMemory.setStatus("BLOCKED");


            SecurityLog log = new SecurityLog();


            log.setMemoryId(savedMemory.getId());

            log.setRiskScore(
                    savedMemory.getRiskScore()
            );


            log.setThreatType(
                    savedMemory.getRiskCategory()
            );


            log.setActionTaken("BLOCKED");


            securityLogService.save(log);


        }
        else{


            savedMemory.setStatus("SAFE");

        }



        return memoryRepository.save(savedMemory);
    }






    private void analyzeRisk(Memory memory){


        MemoryRiskAnalyzer.RiskResult result =
                memoryRiskAnalyzer.analyze(
                        memory.getContent()
                );


        memory.setRiskLevel(
                result.getRiskLevel()
        );


        memory.setRiskScore(
                result.getRiskScore()
        );


        memory.setRiskCategory(
                result.getCategory()
        );


        memory.setRiskReason(
                result.getReason()
        );

    }

}