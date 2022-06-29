package com.example.jwttutorial.Config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity // 기본적인 Web 보안을 활성화함.
public class SecurityConfig extends WebSecurityConfigurerAdapter { // 추가적인 웹 설정을 위해 상속

    // h2-console 하위 모든 요청들과 파비콘 관련 요청은 Spring Security 로직을 수행하지 않도록
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/h2-console/**"
                        , "/favicon.ico"
                );
    }

    @Override // WebSecurityConfigurerAdapter 내부 configure 함수를 오버라이드
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests() // HttpServletRequest를 사용하는 요청들에 대한 접근 제한 설정
                .antMatchers("/api/hello").permitAll() // "/api/hello"에 대한 접근 권한은 인증 없이 접근 허용
                .anyRequest().authenticated(); // 나머지 요청에 대해서는 인증을 받아야 한다.
    }

}
