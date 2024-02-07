package org.issue.example.spring.stored.redis.mapper;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import jakarta.annotation.Resource;
import org.issue.example.spring.stored.login.UsernamePasswordAuthenticationTokenMixin;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.hash.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.*;

/**
 * @Author: Mr.Zhao
 * @Description:
 * @Date:Create：in 2024/2/6 11:48
 * @Modified By:
 */
@Configuration
public class HashMapping {

    @Resource(name = "redisTemplate")
    HashOperations<Object, String, Object> hashOperations;

    ObjectMapper objectMapper = new ObjectMapper()
            // 注册自定义模式
            .registerModule(new ParameterNamesModule(JsonCreator.Mode.PROPERTIES));
    Jackson2HashMapper mapper = new Jackson2HashMapper(objectMapper, false);

    public void writeHash(String key, UsernamePasswordAuthenticationToken person) {
        Map<String, Object> mappedHash = mapper.toHash(person);
        hashOperations.putAll(key, mappedHash);
    }

    public UsernamePasswordAuthenticationToken loadHash(String key) {
        Map<String, Object> loadedHash = hashOperations.entries(key);
        // UsernamePasswordAuthenticationToken没有默认构造函数转换失败
        // mapper.fromHash(loadedHash);
        UsernamePasswordAuthenticationTokenMixin authenticationMixin = new UsernamePasswordAuthenticationTokenMixin(loadedHash);
        return authenticationMixin.getAuthentication();
    }

    public boolean exist(String key) {
        return hashOperations.size(key) > 0;
    }
}
