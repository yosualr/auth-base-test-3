package com.tujuhsembilan.example.services;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class TokenService {

    private final ConcurrentMap<String, String> activeTokens = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> activeSessions = new ConcurrentHashMap<>();

    // Add a token for a user
    public void addToken(String token, String username) {
        activeTokens.put(token, username);
    }

    // Remove a token
    public void removeToken(String token) {
        activeTokens.remove(token);
    }

    // Get username associated with a token
    public String getUsername(String token) {
        return activeTokens.get(token);
    }

    // Add a session for a user
    public void addSession(String username, String token) {
        activeSessions.put(username, token);
    }

    // Remove a session
    public void removeSession(String username) {
        activeSessions.remove(username);
    }

    // Get token associated with a username
    public String getSession(String username) {
        return activeSessions.get(username);
    }
}
