package com.boot.study.service;

import com.boot.study.domain.Account;
import com.boot.study.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private AccountRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = repository.findByUsername(username);

        List<GrantedAuthority> roles = new ArrayList<>();

        if (account == null) {
            //throw new UsernameNotFoundException("User not found with username: " + username);
            roles.add(new SimpleGrantedAuthority("ROLE_LINE"));
            return new User(username, "1234", roles);

        }else{

            if ((account.getRole()).equals("ROLE_ADMIN")) {
                roles.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            } else {
                roles.add(new SimpleGrantedAuthority("ROLE_USER"));
                roles.add(new SimpleGrantedAuthority("ROLE_HI"));
            }
            return new User(account.getUsername(), account.getPassword(), roles);

        }






    }

}
