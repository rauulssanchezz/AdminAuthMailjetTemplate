package com.rauulssanchezz.adminauthmailjettemplate.verificationcode;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface VerificationCodeRepository extends JpaRepository<VerificationCode, Long>{
    Optional<VerificationCode> findByCodeAndUserId(String code, Long userId);
    Optional<VerificationCode> findByUser_Id(Long userId);
}
