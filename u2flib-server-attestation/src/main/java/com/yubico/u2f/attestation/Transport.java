package com.yubico.u2f.attestation;

import java.util.EnumSet;
import java.util.Set;

/**
 * Created by Dain on 2016-02-18.
 */
public enum Transport {
    BT_CLASSIC(1),
    BLE(2),
    USB(4),
    NFC(8);

    private final int bitpos;

    Transport(int bitpos) {
        this.bitpos = bitpos;
    }

    public static Set<Transport> fromInt(int bits) {
        EnumSet<Transport> transports = EnumSet.noneOf(Transport.class);
        for(Transport transport : Transport.values()) {
            if((transport.bitpos & bits) != 0) {
                transports.add(transport);
            }
        }

        return transports;
    }

    public static int toInt(Iterable<Transport> transports) {
        int transportsInt = 0;
        for(Transport transport : transports) {
            transportsInt |= transport.bitpos;
        }
        return transportsInt;
    }

    public static int toInt(Transport...transports) {
        int transportsInt = 0;
        for(Transport transport : transports) {
            transportsInt |= transport.bitpos;
        }
        return transportsInt;
    }
}
