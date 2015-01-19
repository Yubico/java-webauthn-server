package com.yubico.u2f.exceptions;

import com.yubico.u2f.data.DeviceRegistration;

public class DeviceCompromisedException extends Exception {
    private final DeviceRegistration registration;

    public DeviceCompromisedException(DeviceRegistration registration, String message, Throwable cause) {
        super(message, cause);
        this.registration = registration;
    }

    public DeviceCompromisedException(DeviceRegistration registration, String message) {
        super(message);
        this.registration = registration;
    }

    public DeviceRegistration getDeviceRegistration() {
        return registration;
    }
}
