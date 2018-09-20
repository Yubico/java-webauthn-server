package com.yubico.webauthn.exception;

public class RegistrationFailedException extends Exception {

    public RegistrationFailedException(IllegalArgumentException e) {
        super(e);
    }

}
