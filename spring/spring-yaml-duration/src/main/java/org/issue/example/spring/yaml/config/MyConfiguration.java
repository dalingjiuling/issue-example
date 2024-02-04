package org.issue.example.spring.yaml.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @Author: Mr.Zhao
 * @Description:
 * @Date:Create：in 2024/2/2 18:19
 * @Modified By:
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(DurationsProperties.class)
public class MyConfiguration {

    private final DurationsProperties properties;

    MyConfiguration(DurationsProperties properties) {
        this.properties = properties;
    }
}