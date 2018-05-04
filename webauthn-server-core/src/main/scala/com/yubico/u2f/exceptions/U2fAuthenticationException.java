package com.yubico.u2f.exceptions;

/**
 * Base class for exceptions thrown when a U2F authentication ceremony fails.
 */
public class U2fAuthenticationException extends U2fCeremonyException {
    public U2fAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    public U2fAuthenticationException(String message) {
        super(message);
    }
}
