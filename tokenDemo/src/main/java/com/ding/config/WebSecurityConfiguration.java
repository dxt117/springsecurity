package com.ding.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration {

//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return (web) -> {
//            web.ignoring().antMatchers("/index/hello");
//        };
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .antMatchers("/login.html").permitAll()//允许所有请求访问/login.html
                .antMatchers("/index/hello").permitAll()//允许所有请求访问/index/hello
                .anyRequest().authenticated()//其他请求全部认证
                .and()
                .formLogin()//认证方式
//                .usernameParameter("uname")
//                .passwordParameter("pwd")
                .loginPage("/login.html")//指定默认登陆页面 注意：一旦自定义登陆页面后必须指定登陆请求url（下边一行代码）
                .loginProcessingUrl("/login") //指定处理登陆请求url
//                .successForwardUrl("/hello/hello") //(适用于传统项目前后端不分离) 指定认证成功后 forward 跳转的路径   不会根据上一次保存的请求进行跳转
//                .defaultSuccessUrl("/hello/hello") //(适用于传统项目前后端不分离) 认证成功后 redirect 跳转路径  会根据上一次保存的请求进行跳转
                .successHandler(new CustomAuthenticationSuccessHandler()) //(前后端分离项目)认证成功时的处理
//                .failureForwardUrl("") //认证失败后 forward 跳转的路径
//                .failureUrl("") //认证失败后 redirect 跳转路径
                .failureHandler(new CustomAuthenticationFailureHandler())//适用于前后端分离项目
                .and()
                .logout()
                .logoutUrl("/logout") //指定注销登陆url   默认请求方式必须：GET
//                .logoutRequestMatcher(new OrRequestMatcher(  //指定多个注销请求
//                        new AntPathRequestMatcher("/aa","GET"),
//                        new AntPathRequestMatcher("/bb","POST")
//                ))
                .logoutSuccessHandler(new CustomLogoutSuccessHandler()) //适用于前后端分离项目 注销登录后处理
                .invalidateHttpSession(true)   //默认   session会话失效
                .clearAuthentication(true)  //默认   清除认证标记
//                .logoutSuccessUrl("login.html") // 注销后跳转路径
                .and()
                .csrf().disable(); //禁止跨站请求保护

//        http.authorizeRequests().antMatchers("/public/hello").permitAll().anyRequest()
//                .hasRole("USER").and()
//                // Possibly more configuration ...
//                .formLogin() // enable form based log in
//                // set permitAll for all URLs associated with Form Login
//                .permitAll();
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails user = User.withUsername("root")
                .password("{noop}123")
                .roles("USER","ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
