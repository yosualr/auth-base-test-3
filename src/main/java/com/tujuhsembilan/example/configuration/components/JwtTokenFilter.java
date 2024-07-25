package com.tujuhsembilan.example.configuration.components;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.tujuhsembilan.example.services.TokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class JwtTokenFilter extends OncePerRequestFilter {
    private final JwtDecoder jwtDecoder;
    private final TokenService tokenService;

    private static final Logger log = LoggerFactory.getLogger(JwtTokenFilter.class);


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        try {
            Jwt decodedToken = jwtDecoder.decode(token);
            Instant now = Instant.now();
            boolean isExpired = decodedToken.getExpiresAt().isBefore(now);
            String tokenUsername = tokenService.getUsername(token);

            if (isExpired || tokenUsername == null || !tokenUsername.equals(decodedToken.getSubject())) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Token has expired or is invalid");
                return;
            }

            // If token is valid, proceed with the request
            SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(decodedToken.getSubject(), token)
            );


        } catch (JwtException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid token");
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            log.info("Authenticated user: {}", auth.getName());
        } else {
            log.info("No authentication found.");
        }




        chain.doFilter(request, response);
    }
}
