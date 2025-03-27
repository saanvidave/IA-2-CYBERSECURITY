package com.example.wssecurity;

import javax.jws.WebService;

@WebService(endpointInterface = "com.example.wssecurity.SecureService")
public class SecureServiceImpl implements SecureService {
    @Override
    public String sayHello(String name) {
        return "Hello, " + name + "! Your message is secure.";
    }
}

