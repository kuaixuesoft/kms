package com.tuniu.finance.xff.auth.security;

public interface IKeyStore {

	String encryptByPublicKey(String cleartext);

	String decryptByPrivateKey(String ciphertext);

}
