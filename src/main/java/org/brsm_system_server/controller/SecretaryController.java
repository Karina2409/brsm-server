package org.brsm_system_server.controller;

import org.brsm_system_server.entity.Secretary;
import org.brsm_system_server.service.interfaces.ISecretaryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/secretaries")
public class SecretaryController {

    @Autowired
    private ISecretaryService secretaryService;

    @GetMapping("/get-all")
    public List<Secretary> getSecretaries() {
        return secretaryService.findAllSecretaries();
    }

}
