package com.ding.config;

import com.ding.dao.UserDao;
import com.ding.entities.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.ObjectUtils;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor //注意  使用后自动生成必须参数 构造函数  参数前必须使用final修饰  如下  private final UserDao userDao;
public class WebSecurityConfiguration
{

    private final UserDao userDao;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        //授权 Http 请求处理
        http.authorizeHttpRequests(matcherRegistry -> {
            matcherRegistry
                    .antMatchers("/login.html").permitAll()//允许所有请求访问/login.html
                    .antMatchers("/webjars/**", "/webjars/**", "/swagger-resources/**", "/v2/**", "/swagger-ui/**", "/swagger-ui.html", "/swagger-ui/", "/doc.html", "/v3/**").permitAll()//允许所有请求访问swagger 资源
                    .antMatchers("/index/hello").permitAll()//允许所有请求访问/index/hello
                    .anyRequest().authenticated();//其他请求全部认证
        });
        //登录认证处理
        http.formLogin(httpSecurityFormLoginConfigurer -> {
            httpSecurityFormLoginConfigurer
                    .usernameParameter("username")//指定用户名参数名
                    .passwordParameter("password")//指定密码参数名
                    .loginPage("/login.html")//指定默认登陆页面 注意：一旦自定义登陆页面后必须指定登陆请求url（下边一行代码）
                    .loginProcessingUrl("/doLogin") //指定处理登陆请求url
//                    .successForwardUrl("/hello/hello") //(适用于传统项目前后端不分离) 指定认证成功后 forward 跳转的路径   不会根据上一次保存的请求进行跳转
//                    .defaultSuccessUrl("/hello/hello") //(适用于传统项目前后端不分离) 认证成功后 redirect 跳转路径  会根据上一次保存的请求进行跳转
                    .successHandler(authenticationSuccessHandler()) //(前后端分离项目)认证成功时的处理
//                    .failureForwardUrl("") //(适用于传统项目前后端不分离)认证失败后 forward 跳转的路径
//                    .failureUrl("") //(适用于传统项目前后端不分离)认证失败后 redirect 跳转路径
                    .failureHandler(authenticationFailureHandler());//(前后端分离项目)认证失败时的处理
        });
        //注销处理
        http.logout(httpSecurityLogoutConfigurer -> {
            httpSecurityLogoutConfigurer
                    .logoutUrl("/logout") //指定注销登陆url   默认请求方式必须：GET
//                    .logoutRequestMatcher(request -> {//自定义 匹配注销请求   注意：使用自定义时会覆盖默认注销url （上边一行代码）
//                        if (request.getRequestURI().equals("/aa")) {
//                            return request.getMethod().equals("GET");
//                        }
//                        return false;
//                    })
//                    .logoutRequestMatcher(
//                            new OrRequestMatcher(  //自定义 指定多个注销请求  注意：使用自定义时会覆盖默认注销url
//                                    new AntPathRequestMatcher("/aa", "GET"),
//                                    new AntPathRequestMatcher("/bb", "POST")
//                            )
//                    )
                    .logoutSuccessHandler(logoutSuccessHandler()) //适用于前后端分离项目 注销登录后处理
                    .invalidateHttpSession(true)   //默认   session会话失效
                    .clearAuthentication(true);  //默认   清除认证标记
//                    .logoutSuccessUrl("/login.html"); // 注销后跳转路径
        });
        //用户详细信息处理
        http.userDetailsService(userDetailsService());
        //禁止跨站请求保护
        http.csrf().disable();

        return http.build();
    }

    //用户详细信息处理
    @Bean
    public UserDetailsService userDetailsService()
    {
        return username -> {
            //User为 自定义 UserDetails 实现
            User user = userDao.loadUserByUsername(username);
            System.out.println(user.toString());
            if (ObjectUtils.isEmpty(user)) throw new RuntimeException("用户不存在");
            user.setRoles(userDao.getRolesByUid(user.getId()));
            return user;
        };
    }

    //自定义认证成功时的处理
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler()
    {
        return (request, response, authentication) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "登录成功");
            result.put("status", 200);
            result.put("authentication", authentication);
            response.setContentType("application/json;charset=UTF-8");
            String s = new ObjectMapper().writeValueAsString(result);
            response.getWriter().println(s);
        };
    }

    //自定义认证失败时的处理
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler()
    {
        return (request, response, exception) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "登录失败："+exception.getMessage());
            result.put("status", 500);
            response.setContentType("application/json;charset=UTF-8");
            String s = new ObjectMapper().writeValueAsString(result);
            response.getWriter().println(s);
        };
    }

    //自定义退出成功时的处理
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler()
    {
        return (request, response, authentication) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "注销成功");
            result.put("status", 200);
            result.put("authentication", authentication);
            response.setContentType("application/json;charset=UTF-8");
            String s = new ObjectMapper().writeValueAsString(result);
            response.getWriter().println(s);
        };
    }
}
