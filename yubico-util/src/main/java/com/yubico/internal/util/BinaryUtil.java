package com.yubico.internal.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


public class BinaryUtil {

    public static byte[] copy(byte[] bytes) {
        return Arrays.copyOf(bytes, bytes.length);
    }

    /**
     * @param bytes
     *     Bytes to encode
     */
    public static String toHex(byte[] bytes) {
        return Hex.toHexString(bytes);
    }

    /**
     * @param hex
     *     String of hexadecimal digits to decode as bytes.
     */
    public static byte[] fromHex(String hex) {
        return Hex.decode(hex);
    }

    /**
     * Read one byte as an unsigned 8-bit integer.
     * <p>
     * Result is of type Short because Java don't have unsigned types.
     *
     * @return A value between 0 and 255, inclusive.
     */
    public static short getUint8(byte b) {
        // Prepend a zero so we can parse it as a signed int16 instead of a signed int8
        return ByteBuffer.wrap(new byte[]{ 0, b })
            .order(ByteOrder.BIG_ENDIAN)
            .getShort();
    }


    /**
     * Read 2 bytes as a big endian unsigned 16-bit integer.
     * <p>
     * Result is of type Int because Java don't have unsigned types.
     *
     * @return A value between 0 and 2^16- 1, inclusive.
     */
    public static int getUint16(byte[] bytes) {
        if (bytes.length == 2) {
            // Prepend zeroes so we can parse it as a signed int32 instead of a signed int16
            return ByteBuffer.wrap(new byte[] { 0, 0, bytes[0], bytes[1] })
                .order(ByteOrder.BIG_ENDIAN)
                .getInt();
        } else {
            throw new IllegalArgumentException("Argument must be 2 bytes, was: " + bytes.length);
        }
    }


    /**
     * Read 4 bytes as a big endian unsigned 32-bit integer.
     * <p>
     * Result is of type Long because Java don't have unsigned types.
     *
     * @return A value between 0 and 2^32 - 1, inclusive.
     */
    public static long getUint32(byte[] bytes) {
        if (bytes.length == 4) {
            // Prepend zeroes so we can parse it as a signed int32 instead of a signed int16
            return ByteBuffer.wrap(new byte[] { 0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3] })
                .order(ByteOrder.BIG_ENDIAN)
                .getLong();
        } else {
            throw new IllegalArgumentException("Argument must be 4 bytes, was: " + bytes.length);
        }
    }

}
