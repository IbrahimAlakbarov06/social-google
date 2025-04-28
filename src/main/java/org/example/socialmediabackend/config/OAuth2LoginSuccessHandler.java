package org.example.socialmediabackend.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.socialmediabackend.model.User;
import org.example.socialmediabackend.repository.UserRepository;
import org.example.socialmediabackend.service.JwtService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public OAuth2LoginSuccessHandler(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            String token = jwtService.generateToken(userOptional.get());

            // Frontend-ə yönləndir və token-i parametr kimi ötür
            // Bu URL-i öz frontend URL-nizlə əvəz edin
            String redirectUrl = "http://localhost:63342/oauth2/redirect?token=" + token;
            getRedirectStrategy().sendRedirect(request, response, redirectUrl);
        } else {
            // İstifadəçi tapılmadı, xəta
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not found");
        }
    }
}