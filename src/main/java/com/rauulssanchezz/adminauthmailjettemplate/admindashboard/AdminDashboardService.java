package com.rauulssanchezz.adminauthmailjettemplate.admindashboard;

import java.util.ArrayList;
import java.util.List;
import com.rauulssanchezz.adminauthmailjettemplate.verificationcode.VerificationCodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.rauulssanchezz.adminauthmailjettemplate.user.UserService;

@Service
public class AdminDashboardService {

    private final VerificationCodeService verificationCodeService;

    @Autowired
    private UserService userService;

    AdminDashboardService(VerificationCodeService verificationCodeService) {
        this.verificationCodeService = verificationCodeService;
    }

    // Aqui se añaden los repositorios: NoteRepository, etc.

    public List<AdminDashboardItemDto> getDashboardWidgets() {
        List<AdminDashboardItemDto> widgets = new ArrayList<>();

        // Registro de Usuarios
        widgets.add(
                new AdminDashboardItemDto(
                        "Users", userService.getCount(),
                        "bi-people",
                        "/admin/users"));

        /*
         * Verification Codes Widget
         */
        widgets.add(
                new AdminDashboardItemDto(
                        "Verification Codes",
                        verificationCodeService.getCount(),
                        "bi-shield-check",
                        "/admin/verification-codes"));

        // Cuando añadas algo nuevo como Notas, solo vienes aquí y pones:
        // widgets.add(new DashboardItemDto("Notas", noteRepository.count(),
        // "bi-journal", "/admin/notes"));

        return widgets;
    }
}
