package com.qinchy.jwtdemo.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.qinchy.jwtdemo.common.JwtHelper;
import com.qinchy.jwtdemo.model.Audience;
import com.qinchy.jwtdemo.model.ResultMsg;
import com.qinchy.jwtdemo.model.ResultStatusCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Administrator
 * @Desc 这是Bearer的验证方式，需要传入获取到的accessToken
 *      请求http://localhost:8080/jwtdemo/user/getusers时需要在header中加入Authorization，value = "bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJ1bmlxdWVfbmFtZSI6InFpbmN5IiwidXNlcmlkIjoiMSIsImlzcyI6IkFVRElFTkNFX1RFU1QiLCJhdWQiOiJBVURJRU5DRV9JRDEiLCJleHAiOjE1MTc5NzY3NTIsIm5iZiI6MTUxNzk2OTU1Mn0.KqGh4XoAzuYZ8Y80osDxsGGROZ9U5v9FPzvQeOfJMsE"  ,
 *        其中bearer是通过http://localhost:8080/jwtdemo/oauth/token接口获取到的token。调用token接口post，body为raw的json方式，{"clientId":"AUDIENCE_ID1","userName":"qincy","password":"123456"}
 *        token数据格式如下：
 *        {
 *          "errcode": 0,
 *          "errmsg": "OK",
 *          "p2pdata": {
 *              "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJ1bmlxdWVfbmFtZSI6InFpbmN5IiwidXNlcmlkIjoiMSIsImlzcyI6IkFVRElFTkNFX1RFU1QiLCJhdWQiOiJBVURJRU5DRV9JRDEiLCJleHAiOjE1MTc5NzY3NTIsIm5iZiI6MTUxNzk2OTU1Mn0.KqGh4XoAzuYZ8Y80osDxsGGROZ9U5v9FPzvQeOfJMsE",
 *              "tokenType": "bearer",
 *              "expiresIn": 7200
 *              }
 *          }
 */
public class HttpBearerAuthorizeAttribute implements Filter{
    @Autowired  
    private Audience audienceEntity;
  
    @Override  
    public void init(FilterConfig filterConfig) throws ServletException {  
        SpringBeanAutowiringSupport.processInjectionBasedOnServletContext(this,
                filterConfig.getServletContext());  
          
    }  
  
    @Override  
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)  
            throws IOException, ServletException {
        ResultMsg resultMsg;
        HttpServletRequest httpRequest = (HttpServletRequest)request;  
        String auth = httpRequest.getHeader("Authorization");  
        if ((auth != null) && (auth.length() > 7))  
        {  
            String HeadStr = auth.substring(0, 6).toLowerCase();  
            if (HeadStr.compareTo("bearer") == 0)  
            {  
                  
                auth = auth.substring(7, auth.length());   
                if (JwtHelper.parseJWT(auth, audienceEntity.getBase64Secret()) != null)
                {  
                    chain.doFilter(request, response);  
                    return;  
                }  
            }  
        }  
          
        HttpServletResponse httpResponse = (HttpServletResponse) response;  
        httpResponse.setCharacterEncoding("UTF-8");    
        httpResponse.setContentType("application/json; charset=utf-8");   
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);  
  
        ObjectMapper mapper = new ObjectMapper();  
          
        resultMsg = new ResultMsg(ResultStatusCode.INVALID_TOKEN.getErrcode(), ResultStatusCode.INVALID_TOKEN.getErrmsg(), null);
        httpResponse.getWriter().write(mapper.writeValueAsString(resultMsg));  
        return;  
    }  
  
    @Override  
    public void destroy() {  
        // TODO Auto-generated method stub  
          
    }  
}  