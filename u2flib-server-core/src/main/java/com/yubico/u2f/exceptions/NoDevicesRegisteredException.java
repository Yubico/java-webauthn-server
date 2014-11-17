package com.yubico.u2f.exceptions;

public class NoDevicesRegisteredException extends U2fException {
    public NoDevicesRegisteredException() {
        super("The user had no U2F devices registered");
    }
}
