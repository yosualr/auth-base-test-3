package com.tujuhsembilan.example.controller;

import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tujuhsembilan.example.controller.dto.CheckTokenRequestDTO;
import com.tujuhsembilan.example.controller.dto.NoteDto;
import com.tujuhsembilan.example.model.Note;
import com.tujuhsembilan.example.repository.NoteRepo;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/note")
@RequiredArgsConstructor
public class NoteController {

    private final NoteRepo repo;
    private final ModelMapper mdlMap;
    private final JwtDecoder jwtDecoder;

    @GetMapping
    public ResponseEntity<?> getNotes (@RequestHeader("Authorization") String authHeader) {
      String token = authHeader.replace("Bearer ", "");
      String username;
      try {
          Jwt jwt = jwtDecoder.decode(token);
          username = jwt.getSubject();
      } catch (Exception e) {
          return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
      }
        
        return ResponseEntity
                .ok(repo.findByUsername(username)
                .stream()
                .map(o -> mdlMap.map(o, NoteDto.class))
                .collect(Collectors.toSet()));
    }

   @PostMapping
    public ResponseEntity<?> saveNote(@RequestBody NoteDto body, @RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        String username;
        try {
            Jwt jwt = jwtDecoder.decode(token);
            username = jwt.getSubject();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }

        var newNote = mdlMap.map(body, Note.class);
        newNote.setUsername(username);
        newNote = repo.save(newNote);
        return ResponseEntity.status(HttpStatus.CREATED).body(newNote);
    }

}
