package org.issue.example.client.endpoint;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 获取授权码
 */
@RestController
public class Oauth2CodeController {

    /**
     * 获取授权码
     *
     * @return 授权码
     */
    @GetMapping("client/oauth2/code")
    public String getCode(@RequestParam("code") String code) {
        return code;
    }
}
