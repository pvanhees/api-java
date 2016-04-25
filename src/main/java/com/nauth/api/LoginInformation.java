package com.nauth.api;

/**
 * Created by pieter on 4/25/16.
 */
public class LoginInformation {

    private boolean loggedIn;
    private boolean canProvoke;
    private String userId;
    private String loginImage;
    private String publicKey;

    public LoginInformation(boolean loggedIn, boolean canProvoke, String userId, String loginImage, String publicKey) {
        this.loggedIn = loggedIn;
        this.canProvoke = canProvoke;
        this.userId = userId;
        this.loginImage = loginImage;
        this.publicKey = publicKey;
    }

    public boolean isLoggedIn() {
        return loggedIn;
    }

    public boolean isCanProvoke() {
        return canProvoke;
    }

    public String getUserId() {
        return userId;
    }

    public String getLoginImage() {
        return loginImage;
    }

    public String getPublicKey() {
        return publicKey;
    }
}
