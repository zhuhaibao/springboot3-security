package com.jumper.loginform.controller;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
    @PostMapping("resource/{resource}")
    public String orderResource(@PathVariable String resource) {
        return resource + " [protected resource from server]";
    }
}
