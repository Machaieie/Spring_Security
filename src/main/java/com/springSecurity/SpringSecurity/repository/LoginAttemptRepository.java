package com.springSecurity.SpringSecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.springSecurity.SpringSecurity.model.audit.LoginAttempt;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt,Long>{
    
}
