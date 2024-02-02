package org.issue.example.spring.pkce;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * @Author: Mr.Zhao
 * @Description:
 * @Date:Create：in 2024/2/2 9:05
 * @Modified By:
 */

@SpringBootApplication
@EnableConfigurationProperties(OAuth2AuthorizationServerProperties.class)
public class SpringPKCEApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringPKCEApplication.class, args);
        System.out.println("===================success!!!=================");
    }
}
