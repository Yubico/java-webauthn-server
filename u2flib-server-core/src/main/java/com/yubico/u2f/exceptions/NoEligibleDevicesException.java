package com.yubico.u2f.exceptions;

import javax.lang.model.type.ErrorType;

import com.yubico.u2f.data.DeviceRegistration;

import lombok.Getter;

@SuppressWarnings("deprecation")
@Getter
public class NoEligibleDevicesException extends NoEligableDevicesException {

    private final ErrorType type;

    public NoEligibleDevicesException(Iterable<? extends DeviceRegistration> devices, String message, Throwable cause, ErrorType type) {
        super(devices, message, cause);
        this.type = type;
    }

    public NoEligibleDevicesException(Iterable<? extends DeviceRegistration> devices, String message, ErrorType type) {
        super(devices, message);
        this.type = type;
    }

    public NoEligibleDevicesException(Iterable<? extends DeviceRegistration> devices, String message, Throwable cause) {
        this(devices, message, cause, null);
    }

    public NoEligibleDevicesException(Iterable<? extends DeviceRegistration> devices, String message) {
        this(devices, message, (ErrorType) null);
    }

    public enum ErrorType {
        NONE_REGISTERED,
        ALL_COMPROMISED
    }

}
