package com.yubico.webauthn.exception;

public class AssertionFailedException extends Exception {

    public AssertionFailedException(IllegalArgumentException e) {
        super(e);
    }

}
