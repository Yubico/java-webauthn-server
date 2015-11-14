package com.yubico.u2f.exceptions;

import com.google.common.collect.ImmutableList;
import com.yubico.u2f.data.DeviceRegistration;

import java.util.List;

/**
 * @deprecated use {@link NoEligibleDevicesException}
 */
@Deprecated
public class NoEligableDevicesException extends Exception {
    private final List<DeviceRegistration> devices;

    public NoEligableDevicesException(Iterable<? extends DeviceRegistration> devices, String message, Throwable cause) {
        super(message, cause);
        this.devices = ImmutableList.copyOf(devices);
    }

    public NoEligableDevicesException(Iterable<? extends DeviceRegistration> devices, String message) {
        super(message);
        this.devices = ImmutableList.copyOf(devices);
    }

    public Iterable<DeviceRegistration> getDeviceRegistrations() {
        return devices;
    }

    public boolean hasDevices() {
        return !devices.isEmpty();
    }
}
