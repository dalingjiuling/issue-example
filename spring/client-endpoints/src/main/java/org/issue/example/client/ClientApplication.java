package org.issue.example.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @Author: Mr.Zhao
 * @Description:
 * @Date:Create：in 2024/3/13 9:48
 * @Modified By:
 */
@SpringBootApplication
public class ClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClientApplication.class, args);
        System.out.println("===================success!!!=================");
    }
}
