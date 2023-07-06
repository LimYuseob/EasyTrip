package com.project.easytrip.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping("/")
@Controller
public class MainController {

    @GetMapping
    public String Main(){

        return "index";
    }
    @GetMapping("flight")
    public String Flight(){

        return "flight/flight";
    }
    @GetMapping("hotels")
    public String Hotels(){

        return "hotel";
    }
    @GetMapping("cars")
    public String Cars(){

        return "CarsRreView";
    }

    @GetMapping("signup")
    public String signup(){

        return "member/signup";
    }
}
