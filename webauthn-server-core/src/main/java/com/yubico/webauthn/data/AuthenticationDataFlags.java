package com.yubico.webauthn.data;

import lombok.Value;


@Value
public class AuthenticationDataFlags {
    public byte value;

    /** User present */
    public final boolean UP;

    /** User verified */
    public final boolean UV;

    /** Attestation data present */
    public final boolean AT;

    /** Extension data present */
    public final boolean ED;

    public AuthenticationDataFlags(byte value) {
        this.value = value;

        UP = (value & 0x01) > 0;
        UV = (value & 0x04) > 0;
        AT = (value & 0x40) > 0;
        ED = (value & 0x80) > 0;
    }

    /* Reserved bits */
    // public final boolean RFU1 = (value & 0x02) > 0;
    // public final boolean RFU2_1 = (value & 0x08) > 0;
    // public final boolean RFU2_2 = (value & 0x10) > 0;
    // public final boolean RFU2_3 = (value & 0x20) > 0;
}
