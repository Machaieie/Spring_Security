package com.springSecurity.SpringSecurity.aspectJ;

import java.lang.annotation.*;

import com.springSecurity.SpringSecurity.model.Enum.AuditType;
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface LogAction {
    AuditType type();
    String details() default "";
}
