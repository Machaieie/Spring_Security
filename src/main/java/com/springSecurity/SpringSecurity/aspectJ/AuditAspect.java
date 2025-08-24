package com.springSecurity.SpringSecurity.aspectJ;

import java.time.Instant;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.springSecurity.SpringSecurity.model.User;
import com.springSecurity.SpringSecurity.model.Enum.AuditSeverity;
import com.springSecurity.SpringSecurity.model.Enum.AuditType;
import com.springSecurity.SpringSecurity.model.audit.AuditEvent;
import com.springSecurity.SpringSecurity.repository.AuditEventRepository;
import jakarta.servlet.http.HttpServletRequest;
@Aspect
@Component
public class AuditAspect {

    private static final Logger logger = LoggerFactory.getLogger(AuditAspect.class);

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private HttpServletRequest httpRequest;

    // 1️⃣ Captura exceções globais
    @AfterThrowing(pointcut = "execution(* com.springSecurity.SpringSecurity..*(..))", throwing = "ex")
    public void logException(JoinPoint joinPoint, Throwable ex) {
        logger.error("Exception in {}: {}", joinPoint.getSignature(), ex.getMessage(), ex);

        AuditEvent event = new AuditEvent();
        event.setType(AuditType.ACCESS_DENIED);
        event.setSeverity(AuditSeverity.ERROR);
        event.setDetails("Exception: " + ex.getMessage());
        event.setActionName(joinPoint.getSignature().toShortString());
        event.setTimestamp(Instant.now());
        event.setIp(httpRequest.getRemoteAddr());
        event.setUserAgent(httpRequest.getHeader("User-Agent"));

        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof User u) {
            event.setUserId(u.getId());
            event.setUsername(u.getUsername());
        }

        auditEventRepository.save(event);
    }

    // 2️⃣ Loga apenas métodos anotados com @LogAction
    @AfterReturning(pointcut = "@annotation(logAction)", argNames = "joinPoint,logAction")
    public void logAuditedAction(JoinPoint joinPoint, LogAction logAction) {
        AuditEvent event = new AuditEvent();
        event.setType(logAction.type());
        event.setSeverity(AuditSeverity.INFO);
        event.setDetails(logAction.details());
        event.setActionName(joinPoint.getSignature().toShortString());
        event.setTimestamp(Instant.now());
        event.setIp(httpRequest.getRemoteAddr());
        event.setUserAgent(httpRequest.getHeader("User-Agent"));

        User user = null;
        for (Object arg : joinPoint.getArgs()) {
            if (arg instanceof User u) { user = u; break; }
        }
        if (user == null) {
            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof User u) user = u;
        }
        if (user != null) {
            event.setUserId(user.getId());
            event.setUsername(user.getUsername());
        }

        logger.info("Audit log: {} - {}", event.getActionName(), event.getDetails());
        auditEventRepository.save(event);
    }
}
