package com.qinchy.jwtdemo.config;

/**
 * @author Administrator
 */
public enum AuthorizeType {
    BASIC_AUTH("basic", "username and password authorize"),
    BEARER_AUTH("bearer", "token authorize");

    private String type;
    private String remark;

    AuthorizeType(String type, String remark) {
        this.type = type;
        this.remark = remark;
    }

    public String getType() {
        return type;
    }

    public String getRemark() {
        return remark;
    }

}
