package com.ding.controller;


import com.ding.dao.UserDao;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserDao userDao;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/singUp")
    @ApiOperation("注册")
    public void singUp(
            HttpServletResponse response,
            @ApiParam(required = true, value = "username", example = "root")
            @RequestParam(value = "username")
            String username,
            @ApiParam(required = true, value = "password", example = "123")
            @RequestParam(value = "password")
            String password
    ) throws Exception {
        Map<String, Object> result = new HashMap<>();
        if (userDao.addUser(username, passwordEncoder.encode(password)) > 0) {
            result.put("msg", "添加成功！");
            result.put("status", 200);
        } else {
            result.put("msg", "添加失败！");
            result.put("status", 500);
        }
        response.setContentType("application/json;charset=UTF-8");
        String s = new ObjectMapper().writeValueAsString(result);
        response.getWriter().println(s);
    }

    @PostMapping("/updatePassword")
    @ApiOperation("更新密码")
    public void updatePassword(
            HttpServletResponse response,
            @ApiParam(required = true, value = "username", example = "root")
            @RequestParam(value = "username")
            String username,
            @ApiParam(required = true, value = "password", example = "123")
            @RequestParam(value = "password")
            String password
    ) throws Exception {
        Map<String, Object> result = new HashMap<>();
        if (userDao.updatePassword(username, passwordEncoder.encode(password)) > 0) {
            result.put("msg", "更新成功！");
            result.put("status", 200);
        } else {
            result.put("msg", "更新失败！");
            result.put("status", 500);
        }
        response.setContentType("application/json;charset=UTF-8");
        String s = new ObjectMapper().writeValueAsString(result);
        response.getWriter().println(s);
    }
}
