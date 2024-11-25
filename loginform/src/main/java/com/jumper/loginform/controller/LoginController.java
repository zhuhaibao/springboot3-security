package com.jumper.loginform.controller;

import com.alibaba.fastjson2.JSON;
import com.jumper.loginform.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Slf4j
@Controller
@RequiredArgsConstructor
public class LoginController {
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;


    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/")
    public String forward() {
        return "redirect:/";
    }

    @GetMapping("/")
    public String redirect(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("my user authentication :{}", JSON.toJSONString(authentication));
        String sign = jwtUtils.genSign(authentication.getName());
        model.addAttribute("sign", sign);
        return "index";
    }

}
