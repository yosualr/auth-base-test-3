package com.tujuhsembilan.example.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.tujuhsembilan.example.configuration.property.AuthProp;
import com.tujuhsembilan.example.controller.dto.CheckTokenRequestDTO;
import com.tujuhsembilan.example.controller.dto.CheckTokenResponseDTO;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;

@Validated
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class BasicLoginController {

  private final ObjectMapper objMap;

  private final JwtEncoder jwtEncoder;
  private final JwtDecoder jwtDecoder;
  private final AuthProp authProp;

  private final ECKey ecJwk;

  //List ActiveTokens
  private final ConcurrentMap<String, String> activeTokens = new ConcurrentHashMap<>();

  
  @GetMapping("/jwks.json")
  public ResponseEntity<?> jwk() throws JsonProcessingException {
    return ResponseEntity.ok(Map.of("keys", Set.of(objMap.readTree(ecJwk.toPublicJWK().toJSONString()))));
  }

 @PostMapping("/login")
    public ResponseEntity<?> login(@NotNull Authentication auth, @RequestParam(required = false) boolean rememberMe) {
        var authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Instant now = Instant.now();
        long accessTokenValidity = rememberMe ? 10L : 1L; 
        long refreshTokenValidity = rememberMe ? 15L : 3L;

        var accessToken = jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.ES512).build(),
                JwtClaimsSet.builder()
                        .issuer(authProp.getUuid())
                        .audience(List.of(authProp.getUuid()))
                        .subject(((User) auth.getPrincipal()).getUsername())
                        .claim("authorities", authorities)
                        .expiresAt(now.plus(accessTokenValidity, ChronoUnit.MINUTES))
                        .build()));

        var refreshToken = jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.ES512).build(),
                JwtClaimsSet.builder()
                        .issuer(authProp.getUuid())
                        .audience(List.of(authProp.getUuid()))
                        .subject(((User) auth.getPrincipal()).getUsername())
                        .claim("authorities", authorities)
                        .expiresAt(now.plus(refreshTokenValidity, ChronoUnit.MINUTES))
                        .build()));

        activeTokens.put(accessToken.getTokenValue(), ((User) auth.getPrincipal()).getUsername());
        activeTokens.put(refreshToken.getTokenValue(), ((User) auth.getPrincipal()).getUsername());

        return ResponseEntity.ok(Map.of(
                "accessToken", accessToken.getTokenValue(),
                "refreshToken", refreshToken.getTokenValue()
        ));
    }

    @PostMapping("/check-token")
    public ResponseEntity<?> checkToken(@RequestBody CheckTokenRequestDTO requestDTO) {
    
        String token = requestDTO.getToken();
    
        if (token == null || token.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "invalid",
                    "message", "Token is missing"
            ));
        }
    
        try {
            Jwt decodedToken = jwtDecoder.decode(token);
            Instant now = Instant.now();
            boolean isExpired = decodedToken.getExpiresAt().isBefore(now);
            List<String> authorities = decodedToken.getClaimAsStringList("authorities");
    
            String newAccessToken = null;
            String newRefreshToken = null;
            
            if (isExpired) {
                newAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.ES512).build(),
                        JwtClaimsSet.builder()
                                .issuer(authProp.getUuid())
                                .audience(List.of(authProp.getUuid()))
                                .subject(decodedToken.getSubject())
                                .claim("authorities", authorities)
                                .expiresAt(now.plus(1, ChronoUnit.MINUTES)) 
                                .build())).getTokenValue();
    
                newRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.ES512).build(),
                        JwtClaimsSet.builder()
                                .issuer(authProp.getUuid())
                                .audience(List.of(authProp.getUuid()))
                                .subject(decodedToken.getSubject())
                                .claim("authorities", authorities)
                                .expiresAt(now.plus(3, ChronoUnit.MINUTES)) 
                                .build())).getTokenValue();
    
                activeTokens.put(newAccessToken, decodedToken.getSubject());
                activeTokens.put(newRefreshToken, decodedToken.getSubject());
            }
    
            var response = new CheckTokenResponseDTO(
                isExpired ? "expired" : "valid",
                isExpired ? "Access token has expired" : null,
                newAccessToken,
                newRefreshToken,
                decodedToken.getExpiresAt()
            );
    
            if (!activeTokens.containsKey(token)) {
                return ResponseEntity.status(401).body(Map.of(
                        "status", "invalid",
                        "message", "Token is invalid or has been revoked"
                ));
            }
    
            return ResponseEntity.ok(response);
    
        } catch (JwtException e) {
            return ResponseEntity.status(401).body(Map.of(
                    "status", "invalid",
                    "message", e.getMessage()
            ));
        }
    }
    


    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody CheckTokenRequestDTO requestDTO) {
        String token = requestDTO.getToken();

        if (token == null || token.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", "Token is missing"
            ));
        }
    
        if (activeTokens.containsKey(token)) {
            activeTokens.remove(token);
            return ResponseEntity.ok(Map.of("status", "success", "message", "Logged out successfully"));
        } else {
            return ResponseEntity.status(401).body(Map.of(
                    "status", "error",
                    "message", "Invalid or already expired token"
            ));
        }
    }
    
}
