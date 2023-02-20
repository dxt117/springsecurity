package com.ding.config;

import com.ding.dao.UserDao;
import com.ding.entities.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.util.ObjectUtils;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor //注意  使用后自动生成必须参数 构造函数  参数前必须使用final修饰  如下  private final UserDao userDao;
public class WebSecurityConfiguration {

    private final UserDao userDao;

    //全局认证管理器
    private final AuthenticationConfiguration authenticationConfiguration;
    private final DataSource dataSource;

    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //授权 Http 请求处理
        http.authorizeHttpRequests(matcherRegistry -> {
            matcherRegistry
                    .antMatchers("/login.html", "/").permitAll()//允许所有请求访问/login.html
                    .antMatchers("/webjars/**", "/webjars/**", "/swagger-resources/**", "/v2/**", "/swagger-ui/**", "/swagger-ui.html", "/swagger-ui/", "/doc.html", "/v3/**").permitAll()//允许所有请求访问swagger 资源
                    .antMatchers("/index/hello").permitAll()//允许所有请求访问/index/hello
                    .antMatchers("/vc.png").permitAll()
                    .antMatchers("/singUp").permitAll()
                    .anyRequest().authenticated();//其他请求全部认证
        });
        //登录认证处理
//        http.formLogin().loginPage("/login.html");
        http.formLogin(httpSecurityFormLoginConfigurer -> {
            httpSecurityFormLoginConfigurer
//                    .usernameParameter("username")//指定用户名参数名
//                    .passwordParameter("password")//指定密码参数名
                    .loginPage("/login.html")//指定登陆页面 注意：一旦自定义登陆页面后必须指定登陆请求url（下边一行代码）
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
        //异常时处理
        http.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
            httpSecurityExceptionHandlingConfigurer
                    //设置身份验证点入口
                    .authenticationEntryPoint(authenticationEntryPoint())
                    //访问拒绝处理
                    .accessDeniedHandler(accessDeniedHandler());
        });
        //添加过滤器
        http.addFilterAt(verifyFilter(), UsernamePasswordAuthenticationFilter.class);
        //开启记住我功能
        http.rememberMe(httpSecurityRememberMeConfigurer -> {
            httpSecurityRememberMeConfigurer
                    .tokenRepository(persistentTokenRepository())//设置自动登录持久化存储
                    .tokenValiditySeconds(3600)//设置过期时间 毫秒数
                    .userDetailsService(userDetailsService());
        });
        //用户详细信息处理  处理登录逻辑
        http.userDetailsService(userDetailsService());
        //禁止跨站请求保护
        http.csrf().disable();

        return http.build();
    }

    // 自定义验证码filter交给 身份认证管理器管理
    @Bean
    public VerifyFilter verifyFilter() throws Exception {
        VerifyFilter verifyFilter = new VerifyFilter();
        //1.认证 url
        verifyFilter.setFilterProcessesUrl("/doLogin");
        //2.认证 接收参数
        verifyFilter.setCaptchaParameter("captcha");
        //3.指定认证管理器
        verifyFilter.setAuthenticationManager(authenticationManager());
        //4.指定认证成功时处理
        verifyFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        //5.认证失败处理
        verifyFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return verifyFilter;
    }

    //配置密码加密方式
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //使用持久化令牌 实现记住我
    @Bean
    public RememberMeServices rememberMeServices() {
        return new PersistentTokenBasedRememberMeServices(
                UUID.randomUUID().toString(),//参数 1: 自定义一个生成令牌 key 默认 UUID
                userDetailsService(), //参数 2:认证数据源
                persistentTokenRepository());//参数 3:令牌存储方式
    }

    //生成持久化令牌数据库
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setCreateTableOnStartup(false);//只需要没有表时设置为 true 会自动生成remember表
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }

    //用户详细信息处理
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            //User为 自定义 UserDetails 实现
            User user = userDao.loadUserByUsername(username);
            if (ObjectUtils.isEmpty(user)) throw new RuntimeException("用户不存在");
            user.setRoles(userDao.getRolesByUid(user.getId()));
            return user;
        };
    }

    //更新密码处理 (将老旧存储密码 自动更新为加密密码)
    @Bean
    public UserDetailsPasswordService userDetailsPasswordService() {
        return (user, newPassword) -> {
            Integer result = userDao.updatePassword(user.getUsername(), newPassword);
            if (result == 1) {
                ((User) user).setPassword(newPassword);
            }
            return user;
        };
    }


    //自定义认证成功时的处理
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
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

    //自定义 身份验证入口
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, exception) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "必须认证之后才能访问!");
            result.put("status", HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json;charset=UTF-8");
            String s = new ObjectMapper().writeValueAsString(result);
            response.getWriter().println(s);
        };
    }

    //自定义 访问拒绝处理
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, exception) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "权限不足，请联系管理员！");
            result.put("status", HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            String s = new ObjectMapper().writeValueAsString(result);
            response.getWriter().println(s);
        };
    }


    //自定义认证失败时的处理
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "登录失败：" + exception.getMessage());
            result.put("status", 500);
            response.setContentType("application/json;charset=UTF-8");
            String s = new ObjectMapper().writeValueAsString(result);
            response.getWriter().println(s);
        };
    }

    //自定义退出成功时的处理
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
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
