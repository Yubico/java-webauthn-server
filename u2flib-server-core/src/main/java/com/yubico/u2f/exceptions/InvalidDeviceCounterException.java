package com.yubico.u2f.exceptions;

public class InvalidDeviceCounterException extends U2fException {
    public InvalidDeviceCounterException() {
        super("The device's internal counter was was smaller than expected." +
                "Either the device's firmware is noncompliant, or the device has been cloned.");
    }
}
