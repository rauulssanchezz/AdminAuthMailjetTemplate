package com.rauulssanchezz.adminauthmailjettemplate.utils;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;

import com.rauulssanchezz.adminauthmailjettemplate.verificationcode.VerificationCode;

public class GenericUtils {
    public static String generateAlphanumericCode(int length) {
        String characters = "abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder code = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            code.append(characters.charAt(index));
        }

        return code.toString();
    }

    public static boolean isExpired(VerificationCode verificationCode) {
        LocalDateTime now = LocalDateTime.now();
        Duration duration = Duration.between(verificationCode.getCreatedAt(), now);
        
        return duration.toMinutes() > 30;
    }
}
