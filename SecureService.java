package com.example.wssecurity;

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService
public interface SecureService {
    @WebMethod
    String sayHello(String name);
}
