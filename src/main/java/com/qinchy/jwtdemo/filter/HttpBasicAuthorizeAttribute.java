package com.qinchy.jwtdemo.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.qinchy.jwtdemo.common.MD5Util;
import com.qinchy.jwtdemo.model.ResultMsg;
import com.qinchy.jwtdemo.model.ResultStatusCode;
import com.qinchy.jwtdemo.model.UserInfo;
import com.qinchy.jwtdemo.repository.UserInfoRepository;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.WebApplicationContextUtils;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Administrator
 * @Desc 这是基本的验证方式，只需要用户名+密码，然后传入用户名和密码通过base64编码后的字符串即可
 *        请求http://localhost:8080/jwtdemo/user/getuser时需要在header中加入Authorization，value = "basic cWluY3k6MTIzNDU2"  ,
 *        其中cWluY3k6MTIzNDU2是通过BASE64Encoder.encode("qincy:123456".getBytes())出来的。
 */
@SuppressWarnings("restriction")
public class HttpBasicAuthorizeAttribute implements Filter {

    @Autowired
    private static UserInfoRepository userRepositoy;

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        ResultStatusCode resultStatusCode = checkHTTPBasicAuthorize(request);
        if (resultStatusCode != ResultStatusCode.OK) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.setCharacterEncoding("UTF-8");
            httpResponse.setContentType("application/json; charset=utf-8");
            httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            ObjectMapper mapper = new ObjectMapper();

            ResultMsg resultMsg = new ResultMsg(ResultStatusCode.PERMISSION_DENIED.getErrcode(), ResultStatusCode.PERMISSION_DENIED.getErrmsg(), null);
            httpResponse.getWriter().write(mapper.writeValueAsString(resultMsg));
            return;
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {

    }

    private ResultStatusCode checkHTTPBasicAuthorize(ServletRequest request) {
        try {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            String auth = httpRequest.getHeader("Authorization");
            if ((auth != null) && (auth.length() > 6)) {
                String HeadStr = auth.substring(0, 5).toLowerCase();
                if (HeadStr.compareTo("basic") == 0) {
                    auth = auth.substring(6, auth.length());
                    String decodedAuth = getFromBASE64(auth);
                    if (decodedAuth != null) {
                        String[] userArray = decodedAuth.split(":");
                        if (userArray != null && userArray.length == 2) {
                            String name = userArray[0];
                            // 上面Autowired不能自动注入，这里从BeanFactory中重新取一次
                            if(null == userRepositoy){
                                BeanFactory factory = WebApplicationContextUtils.getRequiredWebApplicationContext(request.getServletContext());
                                userRepositoy = (UserInfoRepository) factory.getBean(UserInfoRepository.class);
                            }
                            UserInfo userInfo = userRepositoy.findUserInfoByName(name);
                            if(null != userInfo){
                                String salt = userInfo.getSalt();
                                String password = userArray[1];
                                String md5Password = MD5Util.getMD5(password + salt);
                                if (userArray[0].compareTo(userInfo.getName()) == 0
                                        && md5Password.compareTo(userInfo.getPassword()) == 0) {
                                    return ResultStatusCode.OK;
                                }
                            }
                        }
                    }
                }
            }
            return ResultStatusCode.PERMISSION_DENIED;
        } catch (Exception ex) {
            return ResultStatusCode.PERMISSION_DENIED;
        }

    }

    private String getFromBASE64(String s) {
        if (s == null){
            return null;
        }
        BASE64Decoder decoder = new BASE64Decoder();
        try {
            byte[] b = decoder.decodeBuffer(s);
            return new String(b);
        } catch (Exception e) {
            return null;
        }
    }

//    public static void main(String[] args) {
//        BASE64Encoder encoder =  new BASE64Encoder();
//        String s1 =encoder.encode("qincy:123456".getBytes());
//        System.out.println(s1);
//    }

}  