package org.issue.example.spring.endpoint;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @Author: Mr.Zhao
 * @Description:
 * @Date:Create：in 2024/2/19 15:10
 * @Modified By:
 */
@SpringBootApplication
public class IntrospectionApplication {

    public static void main(String[] args) {
        SpringApplication.run(IntrospectionApplication.class, args);
        System.out.println("===================success!!!=================");
    }
}
