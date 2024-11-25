package com.jumper.oauth2.config;

import com.alibaba.fastjson2.JSON;
import com.jumper.oauth2.filter.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)//禁用csrf
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/loginAuth").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterAfter(jwtAuthFilter, LogoutFilter.class)
                .formLogin(f -> f.loginPage("/login").successForwardUrl("/").permitAll())
                .oauth2Login(o -> o.loginPage("/login").successHandler((request, response, authentication) -> {
                    response.sendRedirect("/");
                }))
                .logout(q -> q.addLogoutHandler(logoutHandler()))
                .exceptionHandling(
                        x -> x.authenticationEntryPoint(authenticationEntryPoint())
                                .accessDeniedHandler(accessDenyHandler())
                )
        ;
        return http.build();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        DefaultOAuth2UserService service = new DefaultOAuth2UserService();
        return userRequest -> {
            OAuth2User user = service.loadUser(userRequest);
            //save to database or 다른 조작 마음 대로
            log.info("oauth2 user detail {}", JSON.toJSONString(user));

            return user;
        };
    }

    @Bean
    public LogoutHandler logoutHandler() {
        return (request, response, authentication) -> {
            //우리 jwt token 실효하게 한다(token expire)

            //clear security context

            SecurityContextHolder.clearContext();
        };
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return ((request, response, authException) -> {
            response.sendRedirect(request.getContextPath() + "/login");
        });
    }

    @Bean
    public AccessDeniedHandler accessDenyHandler() {
        return ((request, response, authException) -> {
            response.sendRedirect(request.getContextPath() + "/login");
        });
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(userDetailsService());
        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false);//认证后不擦除凭证
        return providerManager;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.builder()
                .passwordEncoder(x -> passwordEncoder().encode("123"))
                .username("user")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
