package com.tuniu.finance.xff.auth.security;

public class DesSecurityStrategy implements ISecurityStrategy {

    private String defaultKey;

    public DesSecurityStrategy() {
    }

    public DesSecurityStrategy(String key) {
        this.defaultKey = key;
    }

    @Override
    public String encrypt(String str) throws EncryptException {
        return TripleDES.encrypt(defaultKey, str);
    }

    @Override
    public String decrypt(String str) throws DecryptException {
        return TripleDES.decrypt(defaultKey, str);
    }

    @Override
    public String encrypt(String str, String key) throws EncryptException {
        return TripleDES.encrypt(key, str);
    }

    @Override
    public String decrypt(String str, String key) throws DecryptException {
        return TripleDES.decrypt(key, str);
    }

    @Override
    public String encrypt(String str, String key, String iv) throws EncryptException {
        return TripleDES.encrypt(key, str);
    }

    @Override
    public String decrypt(String str, String key, String iv) throws DecryptException {
        return TripleDES.decrypt(key, str);
    }

}
