package com.qinchy.jwtdemo.model;

/**
 * @author Administrator
 */
public enum ResultStatusCode {
    OK(0, "OK"),
    SYSTEM_ERR(30001, "System error"),
    INVALID_CLIENTID(3002, "Client error"),
    INVALID_USERNAME(3003, "Username error"),
    INVALID_PASSWORD(3004, "Password error"),
    INVALID_TOKEN(3005, "Invalid token"),
    PERMISSION_DENIED(3006, "Permission denied"),
    INVALID_CAPTCHA(30007, "Invalid captcha or captcha overdue");

    private int errcode;
    private String errmsg;

    public int getErrcode() {
        return errcode;
    }

    public void setErrcode(int errcode) {
        this.errcode = errcode;
    }

    public String getErrmsg() {
        return errmsg;
    }

    public void setErrmsg(String errmsg) {
        this.errmsg = errmsg;
    }

    private ResultStatusCode(int Errode, String ErrMsg) {
        this.errcode = Errode;
        this.errmsg = ErrMsg;
    }
}  