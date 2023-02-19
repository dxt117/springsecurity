package com.ding.config;

import org.springframework.security.core.AuthenticationException;


//自定义验证码异常处理类
public class KaptchaNotMatchException extends AuthenticationException
{
  
      public KaptchaNotMatchException(String msg) {
          super(msg);
      }
  
      public KaptchaNotMatchException(String msg, Throwable cause) {
          super(msg, cause);
      }
  }