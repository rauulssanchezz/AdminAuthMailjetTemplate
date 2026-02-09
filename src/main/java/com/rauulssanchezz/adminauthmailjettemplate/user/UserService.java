package com.rauulssanchezz.adminauthmailjettemplate.user;

import java.util.List;
import java.util.Optional;
import com.rauulssanchezz.adminauthmailjettemplate.verificationcode.VerificationCodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.mailjet.client.errors.MailjetException;
import com.rauulssanchezz.adminauthmailjettemplate.utils.mailjet.MailJetUtils;
import com.rauulssanchezz.adminauthmailjettemplate.utils.mailjet.OptionsToSendInterface;

@Service
public class UserService {

    @Autowired
    private VerificationCodeService verificationCodeService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MailJetUtils mailJetUtils;

    public void registerUser(User user) {
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("ROLE_USER");
        }

        userRepository.save(user);

        try {
            mailJetUtils.sendMailJetEmail(user, OptionsToSendInterface.verificationCode);
        } catch (MailjetException e) {
            System.err.println("DETALLE DEL ERROR DE MAILJET: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error sending verification email: " + e.getMessage());
        }
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }

    public long getCount() {
        return userRepository.count();
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public void sendResetPasswordEmail(String email) {
        Optional<User> user = userRepository.findByEmail(email);
        if (user.isPresent()) {
            try {
                mailJetUtils.sendMailJetEmail(user.get(), OptionsToSendInterface.resetPasswordCode);
            } catch (MailjetException e) {
                System.err.println("Error sending reset password email: " + e.getMessage());
            }
        }
    }

    public void resetPassword(Long userId, String code, String newPassword, String confirmPassword) {
        if (!newPassword.equals(confirmPassword)) {
            throw new RuntimeException("Passwords do not match");
        }

        boolean verified = verificationCodeService.verifyPasswordCode(userId, code);

        if (!verified) {
            throw new RuntimeException("Invalid or expired verification code");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public void delete(long id) {
        Optional<User> user = userRepository.findById(id);

        if (user.isEmpty() || user == null) {
            throw new RuntimeException("User does not exist or not found.");
        }

        userRepository.deleteById(id);
    }

}
