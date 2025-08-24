package com.springSecurity.SpringSecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.springSecurity.SpringSecurity.model.User;

public interface UserRepository extends JpaRepository<User, Long>{
    
}
