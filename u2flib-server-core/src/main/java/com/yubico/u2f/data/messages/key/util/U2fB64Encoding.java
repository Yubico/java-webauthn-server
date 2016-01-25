package com.yubico.u2f.data.messages.key.util;

import com.google.common.io.BaseEncoding;

public class U2fB64Encoding {
    private final static BaseEncoding BASE64_ENCODER = BaseEncoding.base64Url().omitPadding();
    private final static BaseEncoding BASE64_DECODER = BaseEncoding.base64Url();

    public static String encode(byte[] decoded) {
        return BASE64_ENCODER.encode(decoded);
    }

    public static byte[] decode(String encoded) {
        return BASE64_DECODER.decode(encoded);
    }
}
