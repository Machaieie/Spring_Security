package com.springSecurity.SpringSecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.springSecurity.SpringSecurity.model.audit.AuditEvent;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long>{
    
}
