package com.cybervault.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class WebController {

    /**
     * Serve the React application for all non-API routes
     * This enables React Router to handle client-side routing
     */
    @GetMapping({"/", "/cybervault", "/cybervault/"})
    public String index() {
        return "index.html";
    }

    /**
     * Handle all other frontend routes by serving index.html
     * This allows React Router to handle the routing client-side
     */
    @GetMapping({"/encrypt", "/decrypt", "/network", "/status"})
    public String frontend() {
        return "index.html";
    }
}