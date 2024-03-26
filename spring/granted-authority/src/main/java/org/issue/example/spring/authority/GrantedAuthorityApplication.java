package org.issue.example.spring.authority;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author: Mr.Zhao
 */
@SpringBootApplication
public class GrantedAuthorityApplication {

    public static void main(String[] args) {
        SpringApplication.run(GrantedAuthorityApplication.class, args);
        System.out.println("===================success!!!=================");
    }
}