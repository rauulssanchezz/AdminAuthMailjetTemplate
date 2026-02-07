package com.rauulssanchezz.adminauthmailjettemplate.utils.mailjet;

import com.mailjet.client.errors.MailjetException;
import com.mailjet.client.MailjetClient;
import com.mailjet.client.MailjetRequest;
import com.mailjet.client.MailjetResponse;
import com.mailjet.client.ClientOptions;
import com.mailjet.client.resource.Emailv31;
import com.rauulssanchezz.adminauthmailjettemplate.user.User;
import com.rauulssanchezz.adminauthmailjettemplate.verificationcode.VerificationCode;
import com.rauulssanchezz.adminauthmailjettemplate.verificationcode.VerificationCodeService;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class MailJetUtils {

    @Value("${app.mailjet.senderemail}")
    private String senderEmail;

    @Value("${app.mailjet.apikey}")
    private String apiKey;

    @Value("${app.mailjet.secretapikey}")
    private String secretApiKey;

    @Autowired
    VerificationCodeService verificationCodeService;
    
    public MailjetResponse sendMailJetEmail(User user, String option) throws MailjetException{
        
        String subject = "";
        String textPart = "";
        String htmlPart = "";

        VerificationCode verificationCode = verificationCodeService.createVerificationCode(user);

        if (option.equalsIgnoreCase(OptionsToSendInterface.resetPasswordCode)) {
            subject = "Change password";
            textPart = "Hi! use this code to change your password: " + verificationCode.getCode();
            htmlPart = getChangePasswordHtml(verificationCode.getCode());
                
        } else if (option.equalsIgnoreCase(OptionsToSendInterface.verificationCode)) {
            subject = "Verify your account";
            textPart = "Hi! use this code to verify your account: " + verificationCode.getCode();
            htmlPart = getVerifyUserHtml(verificationCode.getCode());
                
        } else {
            throw new IllegalArgumentException("Invalid email option: " + option);
        }
        
        ClientOptions options = ClientOptions.builder()
                .apiKey(apiKey)
                .apiSecretKey(secretApiKey)
                .build();

        MailjetClient client = new MailjetClient(options);
        MailjetRequest request = new MailjetRequest(Emailv31.resource)
                .property(Emailv31.MESSAGES, new JSONArray()
                    .put(new JSONObject()
                        .put(Emailv31.Message.FROM, new JSONObject()
                            .put("Email", senderEmail)
                            .put("Name", "AdminAuthMailjetTemplate Admin"))
                        .put(Emailv31.Message.TO, new JSONArray()
                            .put(new JSONObject()
                                .put("Email", user.getEmail())
                                .put("Name", user.getUsername())))
                        .put(Emailv31.Message.SUBJECT, subject)
                        .put(Emailv31.Message.TEXTPART, textPart)
                        .put(Emailv31.Message.HTMLPART, htmlPart)));

        MailjetResponse response = client.post(request);
        return response;
    }

    private String getChangePasswordHtml(String code) {
        return "<div style='background-color: #f4f7f6; padding: 50px; font-family: sans-serif;'>" +
                    "<div style='max-width: 500px; margin: 0 auto; background-color: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-top: 6px solid #0d6efd;'>" +
                        "<div style='text-align: center; margin-bottom: 30px;'>" +
                            "<h2 style='color: #212529; margin-bottom: 10px;'>Change Password</h2>" +
                            "<p style='color: #6c757d; font-size: 16px;'>We have received your request to change your password in <strong>AdminAuthMailjetTemplate</strong>.</p>" +
                        "</div>" +
                        "<div style='background-color: #f8f9fa; border: 2px dashed #dee2e6; border-radius: 8px; padding: 20px; text-align: center; margin-bottom: 30px;'>" +
                            "<span style='display: block; color: #6c757d; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px;'>Your verification code</span>" +
                            "<span style='font-family: monospace; font-size: 36px; font-weight: bold; color: #0d6efd; letter-spacing: 8px;'>" + code + "</span>" +
                        "</div>" +
                        "<p style='color: #6c757d; font-size: 14px; line-height: 1.5; text-align: center;'>" +
                            "This code is valid for the next 30 minutes. If you have not rquested to change your password you can ignore this email." +
                        "</p>" +
                        "<hr style='border: 0; border-top: 1px solid #eee; margin: 30px 0;'>" +
                        "<p style='color: #adb5bd; font-size: 12px; text-align: center;'>" +
                            "© 2026 AdminAuthMailjetTemplate Auth System. Enviado mediante Mailjet." +
                        "</p>" +
                    "</div>" +
                "</div>";
    }

    private String getVerifyUserHtml(String code) {
        return "<div style='background-color: #f4f7f6; padding: 50px; font-family: sans-serif;'>" +
                    "<div style='max-width: 500px; margin: 0 auto; background-color: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-top: 6px solid #0d6efd;'>" +
                        "<div style='text-align: center; margin-bottom: 30px;'>" +
                            "<h2 style='color: #212529; margin-bottom: 10px;'>Verify Your Account</h2>" +
                            "<p style='color: #6c757d; font-size: 16px;'>Welcome to <strong>AdminAuthMailjetTemplate</strong>! Please use the following code to complete your registration.</p>" +
                        "</div>" +
                        "<div style='background-color: #f8f9fa; border: 2px dashed #dee2e6; border-radius: 8px; padding: 25px; text-align: center; margin-bottom: 30px;'>" +
                            "<span style='display: block; color: #6c757d; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px;'>Verification Code</span>" +
                            "<span style='font-family: monospace; font-size: 40px; font-weight: bold; color: #0d6efd; letter-spacing: 10px;'>" + code + "</span>" +
                        "</div>" +
                        "<p style='color: #6c757d; font-size: 14px; line-height: 1.6; text-align: center;'>" +
                            "If you did not create an account with us, you can safely ignore this email." +
                        "</p>" +
                        "<div style='text-align: center; margin-top: 30px;'>" +
                            "<p style='font-size: 13px; color: #adb5bd;'>This is an automated message, please do not reply.</p>" +
                        "</div>" +
                        "<hr style='border: 0; border-top: 1px solid #eee; margin: 30px 0;'>" +
                        "<p style='color: #adb5bd; font-size: 12px; text-align: center;'>" +
                            "© 2026 AdminAuthMailjetTemplate Auth System. Powered by Mailjet." +
                        "</p>" +
                    "</div>" +
                "</div>";
    }
}
