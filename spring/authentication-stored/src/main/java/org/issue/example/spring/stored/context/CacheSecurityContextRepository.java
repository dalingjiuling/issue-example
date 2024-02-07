package org.issue.example.spring.stored.context;

import com.alibaba.fastjson2.JSON;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.issue.example.spring.stored.redis.mapper.HashMapping;
import org.issue.example.spring.stored.util.JwtTokenUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.DigestUtils;
import org.springframework.util.StringUtils;

/**
 * @Author: Mr.Zhao
 * @Description: 自定义数据库认证存储
 * @Date:Create：in 2024/2/5 13:45
 * @Modified By:
 */
public class CacheSecurityContextRepository implements SecurityContextRepository {

    private static final Log log = LogFactory.getLog(CacheSecurityContextRepository.class);
    public static final String ACCESS_TOKEN = "access_token";
    private BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

    HashMapping hashMapping;

    public CacheSecurityContextRepository(HashMapping hashMapping) {
        this.hashMapping = hashMapping;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        log.info("进入loadContext方法");
        HttpServletRequest request = requestResponseHolder.getRequest();
        String token = getToken(request);
        if (null == token) {
            return null;
        }

        if (!StringUtils.hasText(token)) {
            log.warn("请求中token参数为空！");
            return null;
        }
        log.info("获取token：" + token);
        String key = DigestUtils.md5DigestAsHex(token.getBytes());
        log.info("生成缓存key：" + key);

        UsernamePasswordAuthenticationToken authenticationToken = hashMapping.loadHash(key);
        log.info("根据key：" + key + "，获取缓存数据：" + JSON.toJSONString(authenticationToken));
        return new SecurityContextImpl(authenticationToken);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        log.info("进入saveContext方法");

        if (context instanceof SecurityContextImpl securityContext) {
            Authentication authentication = securityContext.getAuthentication();

            if (!authentication.isAuthenticated()) {
                log.warn("用户认证未认证成功！");
                return;
            }

            log.info("用户已认证信息:" + JSON.toJSONString(authentication));

            if (authentication.getPrincipal() instanceof User user) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = (UsernamePasswordAuthenticationToken) authentication;
                String token;
                try {
                    token = JwtTokenUtil.generateToken(user);
                } catch (JOSEException e) {
                    log.error("生成token异常", e);
                    return;
                }
                log.info("获取token：" + token);
                String key = DigestUtils.md5DigestAsHex(token.getBytes());
                log.info("生成缓存key：" + key);

                hashMapping.writeHash(key, usernamePasswordAuthenticationToken);
                log.info("根据key：" + key + "缓存数据完成！");
                request.setAttribute(ACCESS_TOKEN, token);
            }
        }
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        log.info("进入containsContext方法");
        String token = getToken(request);
        if (null == token) {
            return false;
        }
        String key = DigestUtils.md5DigestAsHex(token.getBytes());
        boolean exist = hashMapping.exist(key);
        log.info("key：" + key + "，存在：" + exist);
        return exist;
    }

    private String getToken(HttpServletRequest request) {
        String token = request.getParameter(ACCESS_TOKEN);
        if (!StringUtils.hasText(token)) {
            token = null != request.getAttribute(ACCESS_TOKEN) ? request.getAttribute(ACCESS_TOKEN).toString() : null;
        }
        if (!StringUtils.hasText(token)) {
            token = bearerTokenResolver.resolve(request);
        }
        return token;
    }
}
