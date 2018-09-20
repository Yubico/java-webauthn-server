package com.yubico.webauthn.exception;

/**
 * Thrown when invalid data is given to the server's internal configuration.
 */
public class BadConfigurationException extends Exception {
    public BadConfigurationException(String message) {
        super(message);
    }

    public BadConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
