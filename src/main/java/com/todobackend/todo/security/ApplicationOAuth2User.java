package com.todobackend.todo.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;


public class ApplicationOAuth2User implements OAuth2User {
    private String id;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attribues;

    public ApplicationOAuth2User(String id, Map<String, Object> attribues) {
        this.id = id;
        this.attribues = attribues;
        this.authorities = Collections
                .singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attribues;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getName() {
        return this.id;  // name대신에 id값을 리턴...
    }
}
