package com.tuniu.finance.xff.auth.security;

public class DecryptException extends Exception {
	private static final long serialVersionUID = 7825502310686786981L;

	public DecryptException(String message) {
        super(message);
    }
    
    public DecryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
