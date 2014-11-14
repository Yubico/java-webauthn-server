package com.yubico.u2f.exceptions;

public class InvalidFacetException extends U2fException {
    public InvalidFacetException(String message) {
        super(message);
    }

    public InvalidFacetException(String message, Throwable cause) {
        super(message, cause);
    }
}
