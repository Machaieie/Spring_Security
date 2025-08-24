package com.springSecurity.SpringSecurity.model;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.springSecurity.SpringSecurity.model.Enum.Role;
import com.springSecurity.SpringSecurity.model.Enum.UserState;
import com.springSecurity.SpringSecurity.model.audit.CryptoConverter;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
@Entity @Table(name = "users")
public class User implements UserDetails {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable=false, length=80)
    private String username;

    @Column(nullable=false)
    private String password; 

    @Convert(converter = CryptoConverter.class) 
    @Column(nullable=false, length=320)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false, length=20)
    private UserState userState = UserState.ACTIVE;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false, length=40)
    private Role role = Role.EMPLOYEE;

    private Instant lastLoginAt;
    private Integer failedLoginCount = 0;
    private Boolean mfaEnabled = false;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    public boolean isBlocked() {
        return this.userState == UserState.BLOCKED;
    }

    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked()  { return !isBlocked(); }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return this.userState == UserState.ACTIVE; }
}
