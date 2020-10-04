package com.boot.study.repository;


import com.boot.study.domain.Account;
import org.springframework.data.repository.CrudRepository;

public interface AccountRepository extends CrudRepository<Account, Integer> {
    Account findByUsername(String username);
    Account findByEmail(String email);
    Long deleteByUsername(String username);
}
