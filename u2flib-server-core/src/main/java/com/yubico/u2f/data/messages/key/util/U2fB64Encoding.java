package com.yubico.u2f.data.messages.key.util;

import com.google.common.io.BaseEncoding;

public class U2fB64Encoding {
    private final static BaseEncoding U2F_ENCODING = BaseEncoding.base64Url().omitPadding();

    public static String encode(byte[] decoded) {
        return U2F_ENCODING.encode(decoded);
    }

    public static byte[] decode(String encoded) {
        return U2F_ENCODING.decode(encoded);
    }
}
