package com.example.googleAuth.security;

import com.example.googleAuth.models.RefreshToken;
import com.example.googleAuth.models.User;
import com.example.googleAuth.services.JwtService;
import com.example.googleAuth.services.RefreshTokenService;
import com.example.googleAuth.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @Value("${app.cookie-domain}")
    private String cookieDomain;

    @Value("${app.secure-cookies}")
    private boolean secureCookies;

    @Override
    public void onAuthenticationSuccess(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull Authentication authentication) throws IOException {
        if (response.isCommitted()) {
            log.warn("Response already committed, cannot send cookies");
            return;
        }

        try {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            String email = oidcUser.getEmail();

            User user = userService.findByEmail(email).orElseThrow(()->new IllegalStateException("user not found"));

            String accessToken = jwtService.generateAccessToken(user);

            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

            addTokenCookie(response, "access_token", accessToken, 15 * 60);
            addTokenCookie(response, "refresh_token", refreshToken.getToken(), 7 * 24 * 60 * 60);

            request.getSession().invalidate();

            log.info("User {} authenticated successfully", email);

            getRedirectStrategy().sendRedirect(request, response, frontendUrl + "/dashboard");
        } catch (Exception ex) {
            log.error("Error in OAuth2 success handler", ex);
            getRedirectStrategy().sendRedirect(request, response, frontendUrl + "/login?error=auth_failed");
        }
    }

    private void addTokenCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(secureCookies);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Lax");

        if (!cookieDomain.equals("localhost")) {
            cookie.setDomain(cookieDomain);
        }

        response.addCookie(cookie);
    }
}
