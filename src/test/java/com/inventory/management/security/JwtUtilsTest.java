package com.inventory.management.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {
    
    private JwtUtils jwtUtils;
    
    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(jwtUtils, "jwtSecret", "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437");
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", 86400000);
    }
    
    @Test
    void testGenerateJwtToken() {
        User userDetails = new User("testuser", "password", 
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        
        String token = jwtUtils.generateJwtToken(authentication);
        
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }
    
    @Test
    void testGetUserNameFromJwtToken() {
        User userDetails = new User("testuser", "password", 
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        
        String token = jwtUtils.generateJwtToken(authentication);
        String username = jwtUtils.getUserNameFromJwtToken(token);
        
        assertEquals("testuser", username);
    }
    
    @Test
    void testValidateJwtToken() {
        User userDetails = new User("testuser", "password", 
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        
        String token = jwtUtils.generateJwtToken(authentication);
        
        assertTrue(jwtUtils.validateJwtToken(token));
    }
    
    @Test
    void testValidateInvalidJwtToken() {
        String invalidToken = "invalid.token.here";
        
        assertFalse(jwtUtils.validateJwtToken(invalidToken));
    }
}
