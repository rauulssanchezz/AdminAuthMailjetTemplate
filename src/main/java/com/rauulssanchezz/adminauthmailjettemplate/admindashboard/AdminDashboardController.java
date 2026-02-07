package com.rauulssanchezz.adminauthmailjettemplate.admindashboard;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.rauulssanchezz.adminauthmailjettemplate.user.UserService;
import com.rauulssanchezz.adminauthmailjettemplate.verificationcode.VerificationCodeService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequestMapping("/admin")
public class AdminDashboardController {

    @Autowired
    private AdminDashboardService adminDashboardService;

    @Autowired
    private VerificationCodeService verificationCodeService;

    @Autowired
    private UserService userService;

    @GetMapping("")
    public String redirect() {
        return "redirect:/admin/dashboard";
    }

    @GetMapping("/dashboard")
    public String loadDashboard(Model model) {
        model.addAttribute(
                "widgets",
                adminDashboardService.getDashboardWidgets());
        return "admin/dashboard";
    }

    @GetMapping("/users")
    public String listUsers(Model model) {
        model.addAttribute("users", userService.findAll());
        return "admin/users";
    }

    @GetMapping("/verification-codes")
    public String listVerificationCodes(Model model) {
        model.addAttribute("verificationCodes", verificationCodeService.findAll());
        return "admin/verification-codes";
    }

    @PostMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
        userService.delete(id);
        redirectAttributes.addFlashAttribute("success", "Usuario eliminado correctamente");
        return "redirect:/admin/users";
    }

    @GetMapping("/users/delete/{id}")
    public String deleteUserFallback(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
        // Redirigir si se intenta acceder por GET (por ejemplo, recargando la página o
        // escribiendo la URL)
        redirectAttributes.addFlashAttribute("error", "Acción no válida via GET. Usa el botón de eliminar.");
        return "redirect:/admin/users";
    }

}
