package com.tujuhsembilan.example.controller.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CheckTokenResponseDTO {
    private String status; 
    private String message;
    private String newAccessToken; 
    private String newRefreshToken; 
    private Instant expiresAt;
}