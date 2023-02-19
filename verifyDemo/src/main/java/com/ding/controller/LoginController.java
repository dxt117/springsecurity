package com.ding.controller;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


@Controller
public class LoginController
{

    @GetMapping("/login.html")
    @ApiOperation("跳转到登录页")
    public String login()
    {
        return "login";
    }

    @PostMapping("/doLogin")
    @ApiOperation("登录")
    public String doLogin(
            @ApiParam(required = true, value = "username", example = "root")
            @RequestParam(value = "username")
                    String username,
            @ApiParam(required = true, value = "password", example = "123")
            @RequestParam(value = "password")
                    String password,
            @ApiParam(required = true, value = "captcha", example = "123")
            @RequestParam(value = "captcha")
                    String captcha
    )
    {
        return null;
    }

    @GetMapping("/logout")
    @ResponseBody
    @ApiOperation("注销登录")
    public String logout()
    {
        return null;
    }
}
