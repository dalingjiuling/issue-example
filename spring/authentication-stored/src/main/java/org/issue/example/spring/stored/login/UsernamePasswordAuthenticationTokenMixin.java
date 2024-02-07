package org.issue.example.spring.stored.login;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.*;

/**
 * @Author: Mr.Zhao
 * @Description: 针对UsernamePasswordAuthenticationToken不存再无参构造函数处理
 * @Date:Create：in 2024/2/7 14:47
 * @Modified By:
 */
public class UsernamePasswordAuthenticationTokenMixin {

    private GrantedAuthoritiesMapper authoritiesMapper = new SimpleAuthorityMapper();

    private User principal;

    private String credentials;

    private WebAuthenticationDetails details;

    private UsernamePasswordAuthenticationToken authentication;

    public UsernamePasswordAuthenticationTokenMixin() {
    }

    public UsernamePasswordAuthenticationTokenMixin(Map<String, Object> loadedHash) {
        LinkedHashMap<String, Object> userMap = (LinkedHashMap) loadedHash.get("principal");
        String username = null == userMap.get("username") ? null : (String) userMap.get("username");
        String password = null == userMap.get("password") ? "password" : (String) userMap.get("password");
        boolean accountNonExpired = null == userMap.get("accountNonExpired") ? false : (Boolean) userMap.get("accountNonExpired");
        boolean accountNonLocked = null == userMap.get("accountNonLocked") ? false : (Boolean) userMap.get("accountNonLocked");
        boolean credentialsNonExpired = null == userMap.get("credentialsNonExpired") ? false : (Boolean) userMap.get("credentialsNonExpired");
        boolean enabled = null == userMap.get("enabled") ? false : (Boolean) userMap.get("enabled");

        Set<GrantedAuthority> set = null;
        if (userMap.get("authorities") instanceof ArrayList list) {
            set = new HashSet<>();
            ArrayList<LinkedHashMap<String, String>> authorities = (ArrayList<LinkedHashMap<String, String>>) list;
            for (LinkedHashMap<String, String> map : authorities) {
                GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(map.get("authority"));
                set.add(grantedAuthority);
            }
        }


        this.principal = new User(username, password, enabled, accountNonExpired,
                credentialsNonExpired, accountNonLocked, set);
        this.principal.eraseCredentials();
        this.credentials = this.principal.getPassword();

        if (loadedHash.get("details") instanceof LinkedHashMap linkedHashMap) {
            String remoteAddress = (String) linkedHashMap.get("remoteAddress");
            String sessionId = (String) linkedHashMap.get("sessionId");
            this.details = new WebAuthenticationDetails(remoteAddress, sessionId);
        }

        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(this.principal,
                this.credentials, this.authoritiesMapper.mapAuthorities(this.principal.getAuthorities()));
        result.setDetails(this.details);
        this.authentication = result;
    }

    public User getPrincipal() {
        return principal;
    }

    public void setPrincipal(User principal) {
        this.principal = principal;
    }

    public String getCredentials() {
        return credentials;
    }

    public void setCredentials(String credentials) {
        this.credentials = credentials;
    }

    public WebAuthenticationDetails getDetails() {
        return details;
    }

    public void setDetails(WebAuthenticationDetails details) {
        this.details = details;
    }

    public UsernamePasswordAuthenticationToken getAuthentication() {
        return this.authentication;

    }

    public void setAuthentication(UsernamePasswordAuthenticationToken authentication) {
        this.authentication = authentication;
    }
}