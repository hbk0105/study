package com.boot.study;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.HashMap;

@Controller
@RequestMapping(value = "/")
public class HomeController {

    @GetMapping(value = "/")
    public ModelAndView home(Model model) {
        ModelAndView modelAndView = new ModelAndView();

        modelAndView.setViewName("home");

        ArrayList<HashMap<String, Object>> boardList = new ArrayList<HashMap<String, Object>>();

        HashMap<String, Object> m1 = new HashMap<>();
        m1.put("id","m1");
        m1.put("name","이름sdsds1");

        boardList.add(m1);

        HashMap<String, Object> m2 = new HashMap<>();
        m2.put("id","m2");
        m2.put("name","2323");

        boardList.add(m2);
        modelAndView.addObject("boardList",boardList);

        return modelAndView;
    }



}