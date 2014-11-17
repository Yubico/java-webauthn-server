package com.yubico.u2f.exceptions;

public class NoDevicesRegisteredException extends U2fException {
    public NoDevicesRegisteredException() {
        super("The user has no U2F devices registered");
    }
}
