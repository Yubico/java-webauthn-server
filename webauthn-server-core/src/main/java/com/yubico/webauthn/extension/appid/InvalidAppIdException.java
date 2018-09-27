package com.yubico.webauthn.extension.appid;

public class InvalidAppIdException extends Exception {
    public InvalidAppIdException(String message) {
        super(message);
    }

    public InvalidAppIdException(String message, Throwable cause) {
        super(message, cause);
    }
}
