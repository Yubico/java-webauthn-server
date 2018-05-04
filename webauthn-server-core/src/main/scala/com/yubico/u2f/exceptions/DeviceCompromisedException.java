package com.yubico.u2f.exceptions;

import com.yubico.u2f.data.DeviceRegistration;
import lombok.Getter;

@Getter
public class DeviceCompromisedException extends U2fAuthenticationException {
    private final DeviceRegistration deviceRegistration;

    public DeviceCompromisedException(DeviceRegistration deviceRegistration, String message, Throwable cause) {
        super(message, cause);
        this.deviceRegistration = deviceRegistration;
    }

    public DeviceCompromisedException(DeviceRegistration deviceRegistration, String message) {
        super(message);
        this.deviceRegistration = deviceRegistration;
    }

}
