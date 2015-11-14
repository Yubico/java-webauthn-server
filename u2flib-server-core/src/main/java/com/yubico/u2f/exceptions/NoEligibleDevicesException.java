package com.yubico.u2f.exceptions;

import com.google.common.collect.ImmutableList;
import com.yubico.u2f.data.DeviceRegistration;

import java.util.List;

@SuppressWarnings("deprecation")
public class NoEligibleDevicesException extends NoEligableDevicesException {

    public NoEligibleDevicesException(Iterable<? extends DeviceRegistration> devices, String message, Throwable cause) {
        super(devices, message, cause);
    }

    public NoEligibleDevicesException(Iterable<? extends DeviceRegistration> devices, String message) {
        super(devices, message);
    }

}
