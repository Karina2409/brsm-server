package org.brsm_server.service.interfaces;

import org.brsm_server.entity.Secretary;

import java.util.List;

public interface ISecretaryService {

    List<Secretary> findAllSecretaries();

}
