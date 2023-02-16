package com.ding.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/index")
public class IndexController {

    @PostMapping("/hello")
    public String index() {
        return "Hello Index";
    }

    @PostMapping("/hello2")
    public String index2() {
        return "Hello Index2";
    }
}
