package com.yubico.u2f.exceptions;

import com.yubico.u2f.data.DeviceRegistration;

public class InvalidDeviceCounterException extends DeviceCompromisedException {
    public InvalidDeviceCounterException(DeviceRegistration registration) {
        super(registration, "The device's internal counter was was smaller than expected." +
                "It's possible that the device has been cloned!");
    }
}
