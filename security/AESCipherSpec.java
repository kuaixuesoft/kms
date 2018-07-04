package com.tuniu.finance.xff.auth.security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipherSpec {
	private Cipher cipher;
	private SecretKeySpec key;
	private IvParameterSpec iv;
	private CryptoType type;

	public Cipher getCipher() {
		return cipher;
	}

	public void setCipher(Cipher cipher) {
		this.cipher = cipher;
	}

	public SecretKeySpec getKey() {
		return key;
	}

	public void setKey(SecretKeySpec key) {
		this.key = key;
	}

	public IvParameterSpec getIv() {
		return iv;
	}

	public void setIv(IvParameterSpec iv) {
		this.iv = iv;
	}

	public CryptoType getType() {
		return type;
	}

	public void setType(CryptoType type) {
		this.type = type;
	}
}
