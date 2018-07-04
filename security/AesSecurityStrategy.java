package com.tuniu.finance.xff.auth.security;

import org.apache.commons.codec.DecoderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AesSecurityStrategy implements ISecurityStrategy {

	private String defaultKey;
	private String defaultIV;

	public AesSecurityStrategy(){
	}
	
	public AesSecurityStrategy(String key, String iv){
		this.defaultKey = key;
		this.defaultIV = iv;
	}
	
	@Override
	public String encrypt(String str) throws EncryptException {
		String ciphertext = null;
		try {
			ciphertext = AES.encryptCBC(str, defaultKey, defaultIV);
		} catch (IllegalBlockSizeException |BadPaddingException |InvalidKeyException |NoSuchAlgorithmException |NoSuchPaddingException |InvalidAlgorithmParameterException e) {
			throw new EncryptException("failed to encrypt: "+str,e);
		}

		if(ciphertext==null){
			throw new EncryptException("failed to encrypt: "+str);
		}
		return ciphertext;
	}

	@Override
	public String decrypt(String str) throws DecryptException {
		String cleartext = null;
		try {
			cleartext = AES.decryptCBC(str, defaultKey, defaultIV);
		} catch (DecoderException |IllegalBlockSizeException |BadPaddingException |InvalidKeyException |NoSuchAlgorithmException |NoSuchPaddingException |InvalidAlgorithmParameterException e) {
			throw new DecryptException("failed to decrypt: "+str,e);
		}

		if(cleartext==null){
			throw new DecryptException("failed to decrypt: "+str);
		}
		return cleartext;
	}

	@Override
	public String encrypt(String str, String key) throws EncryptException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String decrypt(String str, String key) throws DecryptException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String encrypt(String str, String key, String iv) throws EncryptException {
		String ciphertext = null;
		try {
			ciphertext = AES.encryptCBC(str, key, iv);
		} catch (IllegalBlockSizeException |BadPaddingException |InvalidKeyException |NoSuchAlgorithmException |NoSuchPaddingException |InvalidAlgorithmParameterException e) {
			throw new EncryptException("failed to encrypt: "+str,e);
		}

		if(ciphertext==null){
			throw new EncryptException("failed to encrypt: "+str);
		}
		return ciphertext;
	}

	@Override
	public String decrypt(String str, String key, String iv) throws DecryptException {
		String cleartext = null;
		try {
			cleartext = AES.decryptCBC(str, key, iv);
		} catch (DecoderException |IllegalBlockSizeException |BadPaddingException |InvalidKeyException |NoSuchAlgorithmException |NoSuchPaddingException |InvalidAlgorithmParameterException e) {
			throw new DecryptException("failed to decrypt: "+str,e);
		}
		if(cleartext==null){
			throw new DecryptException("failed to decrypt: "+str);
		}
		return cleartext;
	}

}
