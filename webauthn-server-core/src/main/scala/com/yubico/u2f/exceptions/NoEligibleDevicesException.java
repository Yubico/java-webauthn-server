package com.yubico.u2f.exceptions;

import com.google.common.collect.ImmutableList;
import com.yubico.u2f.data.DeviceRegistration;
import java.util.List;

public class NoEligibleDevicesException extends U2fAuthenticationException {
    private final List<DeviceRegistration> devices;

    public NoEligibleDevicesException(Iterable<? extends DeviceRegistration> devices, String message, Throwable cause) {
        super(message, cause);
        this.devices = ImmutableList.copyOf(devices);
    }

    public NoEligibleDevicesException(Iterable<? extends DeviceRegistration> devices, String message) {
        super(message);
        this.devices = ImmutableList.copyOf(devices);
    }

    public boolean hasDevices() {
        return !devices.isEmpty();
    }
}
