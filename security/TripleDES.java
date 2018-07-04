package com.tuniu.finance.xff.auth.security;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class TripleDES {
    private static final String ALGORITHM = "DESede"; // 定义 加密算法,可用DES,DESede,Blowfish

    /**
     * 加密
     *
     * @param des3Key
     * @param src
     * @return
     * @throws EncryptException
     */
    public static String encrypt(String des3Key, String src) throws EncryptException {
        Base64 encoder = new Base64();
        byte[] byteMing = null;
        byte[] byteMi = null;
        String strMi = "";
        try {
            byteMing = src.getBytes("utf-8");
            // 加密
            SecretKey deskey = new SecretKeySpec(des3Key.getBytes("utf-8"), ALGORITHM); // 加密
            Cipher c1 = Cipher.getInstance(ALGORITHM);
            c1.init(Cipher.ENCRYPT_MODE, deskey);
            byteMi = c1.doFinal(byteMing);
            strMi = new String(encoder.encode(byteMi));
            return strMi;
        } catch (Exception e) {
            throw new EncryptException("加密失败");
        }
    }

    /**
     * 解密
     *
     * @param des3Key
     * @param src
     * @return
     * @throws DecryptException
     */
    public static String decrypt(String des3Key, String src) throws DecryptException {
        Base64 base64Decoder = new Base64();
        byte[] byteMing = null;
        byte[] byteMi = null;
        String strMing = "";
        try {
            byteMi = base64Decoder.decode(src);
            SecretKey deskey = new SecretKeySpec(des3Key.getBytes(), ALGORITHM); // 解密
            Cipher c1 = Cipher.getInstance(ALGORITHM);
            c1.init(Cipher.DECRYPT_MODE, deskey);
            byteMing = c1.doFinal(byteMi);
            strMing = new String(byteMing, "utf-8");
            return strMing;
        } catch (Exception e) {
            throw new DecryptException("解密失败");
        }
    }
}
