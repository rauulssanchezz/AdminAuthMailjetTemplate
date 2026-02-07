package com.rauulssanchezz.adminauthmailjettemplate.verificationcode;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.rauulssanchezz.adminauthmailjettemplate.user.User;
import com.rauulssanchezz.adminauthmailjettemplate.user.UserRepository;

import jakarta.transaction.Transactional;

@Service
public class VerificationCodeService {
    @Autowired
    VerificationCodeRepository verificationCodeRepository;

    @Autowired
    UserRepository userRepository;

    public VerificationCode createVerificationCode(User user) {
        deleteVerificationCode(user);
        VerificationCode verificationCode = new VerificationCode(user);
        verificationCodeRepository.save(verificationCode);
        return verificationCode;
    }

    public void deleteVerificationCode(User user) {
        Optional<VerificationCode> verificationCode = findByUser_id(user.getId());

        verificationCode.ifPresent(code -> verificationCodeRepository.delete(code));
    }

    public Optional<VerificationCode> findByUser_id(Long id) {
        return verificationCodeRepository.findByUser_Id(id);
    }

    public long getCount() {
        return verificationCodeRepository.count();
    }

    public java.util.List<VerificationCode> findAll() {
        return verificationCodeRepository.findAll();
    }

    @Transactional
    public boolean verifyAccount(Long userId, String inputCode) {
        return verificationCodeRepository.findByCodeAndUserId(inputCode, userId)
                .map(verification -> {
                    if (Duration.between(verification.getCreatedAt(), LocalDateTime.now()).toMinutes() < 30) {

                        User user = verification.getUser();
                        user.setIsActive(true);
                        userRepository.save(user);

                        verificationCodeRepository.delete(verification);
                        return true;
                    }
                    return false;
                })
                .orElse(false);
    }

    @Transactional
    public boolean verifyPasswordCode(Long userId, String inputCode) {
        return verificationCodeRepository.findByCodeAndUserId(inputCode, userId)
                .map(verification -> {
                    if (Duration.between(verification.getCreatedAt(), LocalDateTime.now()).toMinutes() < 30) {
                        verificationCodeRepository.delete(verification);
                        return true;
                    }
                    return false;
                })
                .orElse(false);
    }
}
