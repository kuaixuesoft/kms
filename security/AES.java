package com.tuniu.finance.xff.auth.security;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @Title:AesCBCUtil.java
 * @Package:com.tuniu.finance.xff.vca.utils
 * @author: dengweiwei
 * @date:2016年11月12日 下午3:45:15
 * 算法模式：CBC 密钥
 * 长度：128bits 16位长 
 * 偏移量： 默认 
 * 补码方式：PKCS5Padding 
 * 解密串编码方式：base64
 */

public class AES {
    protected static void assertKey(String key){
        if(key.length()!=16&&key.length()!=32)
            throw new IllegalArgumentException("key's length must be 16/32 bytes");
    }

    protected static void assertIv(String iv){
        if(iv.length()!=16)
            throw new IllegalArgumentException("iv's length must be 16 bytes");
    }

    public static AESCipherSpec getCipherSpec(String key, String iv, CryptoType type) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        assertKey(key);
        assertIv(iv);

        AESCipherSpec cipherSpec = new AESCipherSpec();
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipherSpec.setCipher(cipher);
        cipherSpec.setKey(keySpec);
        cipherSpec.setIv(ivSpec);
        cipherSpec.setType(type);
        return cipherSpec;
    }

    public static String process(String text, AESCipherSpec cipherSpec) throws DecoderException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        if (text == null)
            return text;

        Cipher cipher = cipherSpec.getCipher();
        byte[] raw;

        if (cipherSpec.getType() == CryptoType.ENCRYPT) {
            cipher.init(Cipher.ENCRYPT_MODE, cipherSpec.getKey(), cipherSpec.getIv());
            raw = cipher.doFinal(text.getBytes());
            return Hex.encodeHexString(raw);
        } else if (cipherSpec.getType() == CryptoType.DECRYPT) {
            cipher.init(Cipher.DECRYPT_MODE, cipherSpec.getKey(), cipherSpec.getIv());
            raw = Hex.decodeHex(text.toCharArray());
            raw = cipher.doFinal(raw);
            return new String(raw);
        } else {
            throw new IllegalArgumentException(cipherSpec.getType() + " is not supported by AES");
        }
    }

    public static String encryptCBC(String plainText, String key, String iv)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException {
        AESCipherSpec cipherSpec = getCipherSpec(key, iv, CryptoType.ENCRYPT);
        Cipher cipher = cipherSpec.getCipher();
        cipher.init(Cipher.ENCRYPT_MODE, cipherSpec.getKey(), cipherSpec.getIv());
        byte[] raw;
        raw = cipher.doFinal(plainText.getBytes());
        return Hex.encodeHexString(raw);
    }

    public static String decryptCBC(String cipherText, String key, String iv)
            throws DecoderException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        AESCipherSpec cipherSpec = getCipherSpec(key, iv, CryptoType.DECRYPT);
        Cipher cipher = cipherSpec.getCipher();
        cipher.init(Cipher.DECRYPT_MODE, cipherSpec.getKey(), cipherSpec.getIv());
        byte[] raw;
        raw = Hex.decodeHex(cipherText.toCharArray());
        raw = cipher.doFinal(raw);
        return new String(raw);
    }
}

