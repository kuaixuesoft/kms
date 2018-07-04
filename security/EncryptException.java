package com.tuniu.finance.xff.auth.security;

public class EncryptException extends Exception {
	private static final long serialVersionUID = -5597265672961648384L;

	public EncryptException(String message) {
        super(message);
    }
    
    public EncryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
