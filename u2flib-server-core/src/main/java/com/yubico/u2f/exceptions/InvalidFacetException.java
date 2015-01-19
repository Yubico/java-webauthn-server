package com.yubico.u2f.exceptions;

public class InvalidFacetException extends U2fBadInputException {
    public InvalidFacetException(String message) {
        super(message);
    }

    public InvalidFacetException(String message, Throwable cause) {
        super(message, cause);
    }
}
