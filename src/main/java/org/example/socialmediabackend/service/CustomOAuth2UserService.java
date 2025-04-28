package org.example.socialmediabackend.service;

import org.example.socialmediabackend.model.User;
import org.example.socialmediabackend.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Google-dan məlumatları əldə et
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        // İstifadəçini bazada axtar və ya yeni istifadəçi yarat
        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        if (userOptional.isEmpty()) {
            user = new User();
            user.setEmail(email);
            user.setUsername(email.split("@")[0]); // E-poçt adresindən istifadəçi adı yarada bilərsiniz
            user.setPassword(""); // Google authentication istifadə edənlər üçün şifrə lazım deyil
            user.setEnabled(true);
            userRepository.save(user);
        }

        return oAuth2User;
    }
}