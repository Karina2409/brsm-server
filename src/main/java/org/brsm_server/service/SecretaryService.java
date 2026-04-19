package org.brsm_server.service;

import org.brsm_server.entity.Secretary;
import org.brsm_server.repository.SecretaryRepository;
import org.brsm_server.service.interfaces.ISecretaryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SecretaryService implements ISecretaryService {

    @Autowired
    private SecretaryRepository secretaryRepository;

    @Override
    public List<Secretary> findAllSecretaries(){
        return secretaryRepository.findAll();
    }

}
