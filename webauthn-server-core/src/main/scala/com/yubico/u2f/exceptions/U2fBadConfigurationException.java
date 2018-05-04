package com.yubico.u2f.exceptions;

public class U2fBadConfigurationException extends Exception {
    public U2fBadConfigurationException(String message) {
        super(message);
    }

    public U2fBadConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
