/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package com.yubico.u2f.data.messages.key.util;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

/**
 * Provides an easy way to read a byte array in chunks.
 */
public class ByteInputStream extends DataInputStream {

    public ByteInputStream(byte[] data) {
        super(new ByteArrayInputStream(data));
    }

    public byte[] read(int numberOfBytes) throws IOException {
        byte[] readBytes = new byte[numberOfBytes];
        readFully(readBytes);
        return readBytes;
    }

    public byte[] readAll() throws IOException {
        byte[] readBytes = new byte[available()];
        readFully(readBytes);
        return readBytes;
    }

    public int readInteger() throws IOException {
        return readInt();
    }

    public byte readSigned() throws IOException {
        return readByte();
    }

    public int readUnsigned() throws IOException {
        return readUnsignedByte();
    }
}
