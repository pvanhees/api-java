package com.nauth.api;


/**
 * Represents an irrecoverable n-Auth server exception. 
 * 
 * Examples include:
 * - no connection to server
 * - internal server errors (i.e. database failures etc), corresponding to HTTP 500 errors
 * - SSL connection problems
 */
public class NAuthServerException extends Exception {

	private static final long serialVersionUID = 1L;

	public NAuthServerException() {
		super();
	}

	public NAuthServerException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public NAuthServerException(String message, Throwable cause) {
		super(message, cause);
	}

	public NAuthServerException(String message) {
		super(message);
	}
	
	public NAuthServerException(Throwable cause){
		super(cause);
	}

}
