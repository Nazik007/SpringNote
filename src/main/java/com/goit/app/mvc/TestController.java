package com.goit.app.mvc;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class TestController {

    @RequestMapping("/test")
    public String test(){
        return "Test message";
    }
    @RequestMapping(value = "/hello", method = {RequestMethod.GET})
    public ModelAndView hello() {
        ModelAndView result = new ModelAndView("test/hello");
        result.addObject("hello", "Hello world!");
        return result;
    }
}

