package com.example.googleAuth.services;

import com.example.googleAuth.models.AuthProvider;
import com.example.googleAuth.models.User;
import com.example.googleAuth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Transactional
    public User createOrUpdateUser(String email, String name, String picture, String providerId){
        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            User user = existingUser.get();
            user.setName(name);
            user.setProfilePicture(picture);
            user.setProviderId(providerId);
            return userRepository.save(user);
        }else {
            User newUser = User.builder()
                    .email(email)
                    .name(name)
                    .profilePicture(picture)
                    .provider(AuthProvider.GOOGLE)
                    .providerId(providerId)
                    .build();
            return userRepository.save(newUser);
        }
    }
}
