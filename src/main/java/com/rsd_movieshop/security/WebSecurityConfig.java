package com.rsd_movieshop.security;

import org.hibernate.annotations.Immutable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService customUserDetailsService;

    public WebSecurityConfig(CustomUserDetailsService customUserDetailsService) {
        this.customUserDetailsService = customUserDetailsService;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return this.customUserDetailsService;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());

        return authenticationProvider;
    }

    public UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter() throws Exception {
        JsonUsernamePasswordAuthenticationFilter authenticationFilter
                = new JsonUsernamePasswordAuthenticationFilter();
        authenticationFilter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler());
        authenticationFilter.setAuthenticationManager(authenticationManagerBean());

        return authenticationFilter;
    }

    @Bean
    public CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler(){
        return new CustomAuthenticationSuccessHandler();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        final CorsConfiguration configurationForCors = new CorsConfiguration();
        configurationForCors.applyPermitDefaultValues();
        configurationForCors.setAllowedOrigins(List.of("http://127.0.0.1:5500/"));
        configurationForCors.setAllowedHeaders(List.of("*"));
        configurationForCors.setExposedHeaders(List.of("*"));
        configurationForCors.setAllowCredentials(true);

        http.formLogin()
                .loginProcessingUrl("/login")
                .permitAll();

        http.cors().configurationSource(request -> configurationForCors);
    	
    	http.authorizeRequests()
    	.antMatchers("/api/**").permitAll();
    	
    	http.authorizeRequests()
    			.antMatchers("/h2-console/**").permitAll();
    	
        http.authorizeRequests()
        .antMatchers("/api/admin/**")
        .access("hasRole('ROLE_ADMIN')");
        
        http.authorizeRequests()
        		.antMatchers("/api/user/**")
        		.access("hasRole('ROLE_USER')");
        
        http.csrf().disable();
        http.headers().frameOptions().disable();


        http.authorizeRequests()
                .anyRequest()
                .authenticated();

        http.csrf()
                .disable();


        
        http.logout()
        .logoutUrl("/logout")
        .permitAll();
        

        http.addFilterAt(
                usernamePasswordAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter.class
        );

        http.exceptionHandling()
                .accessDeniedHandler(
                        (httpServletRequest, httpServletResponse, e) ->
                                httpServletResponse.sendError(
                                        HttpServletResponse.SC_FORBIDDEN
                                )
                )
                .authenticationEntryPoint(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
                );
        

    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }


    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }

}
