package org.issue.example.spring.stored.login;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.issue.example.spring.stored.context.CacheSecurityContextRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;

/**
 * @Author: Mr.Zhao
 * @Description: 登录成功跳转处理
 * @Date:Create：in 2024/2/6 19:01
 * @Modified By:
 */
public class LoginRequestAwareAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private static final Log log = LogFactory.getLog(LoginRequestAwareAuthenticationSuccessHandler.class);

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {

        Object tokenObject = request.getAttribute(CacheSecurityContextRepository.ACCESS_TOKEN);
        String token = "";
        if (null != tokenObject) {
            token = tokenObject.toString();
        }
        String targetUrl = "/home?" + CacheSecurityContextRepository.ACCESS_TOKEN + "=" + token;
        this.redirectStrategy.sendRedirect(request, response, targetUrl);
    }
}
