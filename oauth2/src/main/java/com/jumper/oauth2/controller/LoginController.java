package com.jumper.oauth2.controller;

import com.alibaba.fastjson2.JSON;
import com.jumper.oauth2.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
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
        //for loginForm
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            log.info("loginForm authentication :{}", JSON.toJSONString(authentication));
        } else if (authentication instanceof OAuth2AuthenticationToken) {// for OAuth2 Login
            log.info("oauth2 authentication :{}", JSON.toJSONString(authentication));
        }
        String sign = jwtUtils.genSign(authentication.getName());
        model.addAttribute("sign", sign);
        return "index";
    }

}
