package com.example.googleAuth.security;

import com.example.googleAuth.models.User;
import com.example.googleAuth.services.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService extends OidcUserService {

    private final UserService userService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        try {
            return processOidcUser(oidcUser);
        } catch (Exception e){
            log.error("Error processing OIDC user", e);
            throw new OAuth2AuthenticationException("Error processing user info");
        }
    }

    //map google user
    private OidcUser processOidcUser(OidcUser oidcUser) {
        String email = oidcUser.getEmail();
        String name = oidcUser.getName();
        String picture = oidcUser.getPicture();
        String providerId = oidcUser.getSubject();

        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("Email not provided by Google");
        }

        User user = userService.createOrUpdateUser(email, name, picture, providerId);
        log.info("User authenticated: {}", email);

        return oidcUser;
    }

}
