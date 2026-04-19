package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Secretary;

import java.util.List;

public interface ISecretaryService {

    List<Secretary> findAllSecretaries();

}
