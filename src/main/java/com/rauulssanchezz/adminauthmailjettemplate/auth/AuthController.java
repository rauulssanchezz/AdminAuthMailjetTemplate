package com.rauulssanchezz.adminauthmailjettemplate.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

import com.rauulssanchezz.adminauthmailjettemplate.user.User;
import com.rauulssanchezz.adminauthmailjettemplate.user.UserService;
import com.rauulssanchezz.adminauthmailjettemplate.verificationcode.VerificationCodeService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.ui.Model;

@Controller
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private VerificationCodeService verificationCodeService;

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error, Model model) {
        if (error != null) {
            model.addAttribute("loginError", "Invalid credentials or account not verified.");
        }
        return "auth/login";
    }

    @GetMapping("/register")
    public String showRegisterPage(Model model) {
        model.addAttribute("user", new User());
        return "auth/register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute("user") User user, RedirectAttributes redirectAttributes) {
        try {
            userService.registerUser(user);
            redirectAttributes.addFlashAttribute("userId", user.getId());
            return "redirect:/auth/verify-account";
        } catch (RuntimeException e) {
            return "redirect:/auth/register?error";
        }
    }

    @GetMapping("/verify-account")
    public String showVerifyPage(
            @RequestParam(value = "email", required = false) String email,
            Model model) {
        if (model.containsAttribute("userId")) {
            return "auth/verify-account";
        }

        if (email != null) {
            userService.findByEmail(email).ifPresent(user -> {
                model.addAttribute("userId", user.getId());
            });
            return "auth/verify-account";
        }

        return "redirect:/auth/resend-code-page";
    }

    @GetMapping("/reset-password")
    public String showVerifyPasswordPage(
            @RequestParam(value = "email", required = false) String email,
            Model model) {
        if (model.containsAttribute("userId")) {
            return "auth/reset-password";
        }

        if (email != null) {
            var user = userService.findByEmail(email);
            if (user.isPresent()) {
                model.addAttribute("userId", user.get().getId());
                return "auth/reset-password";
            }
        }

        return "redirect:/auth/forgot-password?error";
    }

    @GetMapping("/forgot-password")
    public String showForgotPasswordPage() {
        return "auth/forgot-password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPassword(@RequestParam("email") String email, RedirectAttributes redirectAttributes) {
        userService.sendResetPasswordEmail(email);
        return "redirect:/auth/reset-password?email=" + email;
    }

    @PostMapping("/reset-password")
    public String verifyPassword(
            @RequestParam("userId") Long userId,
            @RequestParam("code") String code,
            @RequestParam("newPassword") String newPassword,
            @RequestParam("confirmPassword") String confirmPassword,
            RedirectAttributes redirectAttributes) {
        try {
            userService.resetPassword(userId, code, newPassword, confirmPassword);
            redirectAttributes.addFlashAttribute("success", "Password reset successfully! You can now log in.");
            return "redirect:/auth/login";
        } catch (RuntimeException e) {
            redirectAttributes.addFlashAttribute("userId", userId);
            redirectAttributes.addFlashAttribute("error", e.getMessage());
            return "redirect:/auth/reset-password";
        }
    }

    @PostMapping("/verify-account")
    public String verifyAccount(
            @RequestParam("userId") Long userId,
            @RequestParam("inputCode") String inputCode,
            RedirectAttributes redirectAttributes) {
        Boolean verificated = verificationCodeService.verifyAccount(userId, inputCode);

        if (verificated) {
            redirectAttributes.addFlashAttribute("success", "Account verified successfully! You can now log in.");
            return "auth/login";
        } else {
            redirectAttributes.addFlashAttribute("userId", userId);
            redirectAttributes.addFlashAttribute("error", "Invalid or expired code. Please try again.");
            return "redirect:/auth/verify-account";
        }
    }

}
