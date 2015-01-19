package com.yubico.u2f.exceptions;

public class NoDevicesRegisteredException extends Exception {
    public NoDevicesRegisteredException() {
        super("The user has no U2F devices registered");
    }
}
