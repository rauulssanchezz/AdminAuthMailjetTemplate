package com.rauulssanchezz.adminauthmailjettemplate.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.rauulssanchezz.adminauthmailjettemplate.user.User;
import com.rauulssanchezz.adminauthmailjettemplate.user.UserRepository;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${app.admin.email}")
    private String adminEmail;

    @Value("${app.admin.password}")
    private String adminPassword;

    @Value("${app.admin.username")
    private String adminUserName;

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.findByEmail(adminEmail).isEmpty()) {
            User admin = new User();
            admin.setEmail(adminEmail);
            admin.setUsername(adminUserName);
            // Seteamos la contraseña encriptada
            admin.setPassword(passwordEncoder.encode(adminPassword));
            admin.setRole("ROLE_ADMIN");
            admin.setIsActive(true);
            
            userRepository.save(admin);
            System.out.println(">>> Superuser creado: " + adminEmail + " / " + adminPassword);
        }
    }
}
