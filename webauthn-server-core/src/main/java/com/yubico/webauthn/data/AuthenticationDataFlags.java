package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@ToString
@EqualsAndHashCode
public final class AuthenticationDataFlags {
    public final byte value;

    /** User present */
    public final boolean UP;

    /** User verified */
    public final boolean UV;

    /** Attestation data present */
    public final boolean AT;

    /** Extension data present */
    public final boolean ED;

    @JsonCreator
    public AuthenticationDataFlags(@JsonProperty("value") byte value) {
        this.value = value;

        UP = (value & Bitmasks.UP) != 0;
        UV = (value & Bitmasks.UV) != 0;
        AT = (value & Bitmasks.AT) != 0;
        ED = (value & Bitmasks.ED) != 0;
    }

    private static final class Bitmasks {
        static final byte UP = 0x01;
        static final byte UV = 0x04;
        static final byte AT = 0x40;
        static final byte ED = -0x80;

        /* Reserved bits */
        // final boolean RFU1 = (value & 0x02) > 0;
        // final boolean RFU2_1 = (value & 0x08) > 0;
        // final boolean RFU2_2 = (value & 0x10) > 0;
        // static final boolean RFU2_3 = (value & 0x20) > 0;
    }

}
