package com.example.googleAuth.dto;

import jakarta.annotation.security.DenyAll;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
    private Long id;
    private String email;
    private String name;
    private String profilePicture;
}
