package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.internal.util.BinaryUtil;
import com.yubico.internal.util.U2fB64Encoding;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.data.exception.HexException;
import com.yubico.internal.util.json.JsonStringSerializable;
import com.yubico.internal.util.json.JsonStringSerializer;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;
import org.bouncycastle.util.Arrays;

/**
 * An immutable byte array with support for encoding/decoding to/from Base64URL encoding.
 */
@JsonSerialize(using = JsonStringSerializer.class)
@EqualsAndHashCode
@ToString(of = { "base64" }, includeFieldNames = false)
public class ByteArray implements JsonStringSerializable {

    @NonNull
    private final byte[] bytes;

    @NonNull
    private final String base64;

    /**
     * Create a new instance by copying the contents of <code>bytes</code>.
     */
    public ByteArray(@NonNull byte[] bytes) {
        this.bytes = BinaryUtil.copy(bytes);
        this.base64 = U2fB64Encoding.encode(this.bytes);
    }

    @JsonCreator
    private ByteArray(String base64) throws Base64UrlException {
        try {
            this.bytes = U2fB64Encoding.decode(base64);
        } catch (U2fBadInputException e) {
            throw new Base64UrlException("Invalid Base64Url encoding: " + base64, e);
        }
        this.base64 = base64;
    }

    /**
     * Create a new instance by decoding <code>base64</code> as Base64Url data.
     *
     * @throws Base64UrlException if <code>base64</code> is not valid Base64Url data.
     */
    public static ByteArray fromBase64Url(@NonNull final String base64) throws Base64UrlException {
        return new ByteArray(base64);
    }

    /**
     * Create a new instance by decoding <code>hex</code> as hexadecimal data.
     *
     * @throws HexException if <code>hex</code> is not valid hexadecimal data.
     */
    public static ByteArray fromHex(@NonNull final String hex) throws HexException {
        try {
            return new ByteArray(BinaryUtil.fromHex(hex));
        } catch (Exception e) {
            throw new HexException("Invalid hexadecimal encoding: " + hex, e);
        }
    }

    /**
     * @return a new instance containing a copy of this instance followed by a copy of <code>tail</code>.
     */
    public ByteArray concat(@NonNull ByteArray tail) {
        return new ByteArray(Arrays.concatenate(this.bytes, tail.bytes));
    }

    /**
     * @return a copy of the raw byte contents.
     */
    public byte[] getBytes() {
        return BinaryUtil.copy(bytes);
    }

    /**
     * @return the content bytes encoded as Base64Url data.
     */
    public String getBase64Url() {
        return base64;
    }

    /**
     * @return the content bytes encoded as hexadecimal data.
     */
    public String getHex() {
        return BinaryUtil.toHex(bytes);
    }

    /**
     * Used by JSON serializer.
     */
    @Override
    public String toJsonString() {
        return base64;
    }

}
