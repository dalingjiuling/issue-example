package org.issue.example.spring.stored;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @Author: Mr.Zhao
 * @Description: 自定义自定义认证存储位置
 * @Date:Create：in 2024/2/5 13:42
 * @Modified By:
 */
@SpringBootApplication
public class SpringStoredApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringStoredApplication.class, args);
        System.out.println("===================success!!!=================");
    }
}