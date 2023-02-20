package com.ding.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.util.ObjectUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


//自定义验证码过滤器实现
@Getter
@Setter
public class VerifyFilter extends UsernamePasswordAuthenticationFilter
{
    public static final String FORM_CAPTCHA_KEY = "captcha";
    private String captchaParameter = FORM_CAPTCHA_KEY;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException
    {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        //1.获取请求中的验证码
        String captcha = request.getParameter("captcha");
        //2.获取 session 中验证码
        String sessionVerifyCode = (String) request.getSession().getAttribute("captcha");
        //获取 是否记住我
        String remember = request.getParameter(AbstractRememberMeServices.DEFAULT_PARAMETER);
        if (!ObjectUtils.isEmpty(remember)) {
            request.setAttribute(AbstractRememberMeServices.DEFAULT_PARAMETER, remember);
        }
        if (ObjectUtils.isEmpty(captcha) || ObjectUtils.isEmpty(sessionVerifyCode) || !captcha.equalsIgnoreCase(sessionVerifyCode)) {
            throw new KaptchaNotMatchException("验证码不匹配!");
        }
        return super.attemptAuthentication(request, response);
    }
}
