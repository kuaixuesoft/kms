package com.tuniu.finance.xff.auth.security;

public interface ISecurityStrategy {
	String encrypt(String str) throws EncryptException;
	String decrypt(String str) throws DecryptException;
	String encrypt(String str, String key) throws EncryptException;
	String decrypt(String str, String key) throws DecryptException;
	String encrypt(String str, String key, String iv) throws EncryptException;
	String decrypt(String str, String key, String iv) throws DecryptException;
}
