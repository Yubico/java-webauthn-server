package com.yubico.u2f.exceptions;

/**
 * Base class for exceptions thrown when a U2F registration or authentication ceremony fails.
 */
public class U2fCeremonyException extends Exception {
    public U2fCeremonyException(String message, Throwable cause) {
        super(message, cause);
    }

    public U2fCeremonyException(String message) {
        super(message);
    }
}
