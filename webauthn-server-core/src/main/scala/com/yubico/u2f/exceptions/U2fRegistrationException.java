package com.yubico.u2f.exceptions;

/**
 * Base class for exceptions thrown when a U2F registration ceremony fails.
 */
public class U2fRegistrationException extends U2fCeremonyException {
    public U2fRegistrationException(String message, Throwable cause) {
        super(message, cause);
    }

    public U2fRegistrationException(String message) {
        super(message);
    }
}
