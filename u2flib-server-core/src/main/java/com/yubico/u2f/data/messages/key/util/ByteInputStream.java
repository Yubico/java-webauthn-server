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
//  ByteArrayInputStream cannot throw IOExceptions, so this class is converting checked exceptions to unchecked.
public class ByteInputStream extends DataInputStream {

    public ByteInputStream(byte[] data) {
        super(new ByteArrayInputStream(data));
    }

    public byte[] read(int numberOfBytes) {
        byte[] readBytes = new byte[numberOfBytes];
        try {
            readFully(readBytes);
        } catch (IOException e) {
            throw new AssertionError();
        }
        return readBytes;
    }

    public byte[] readAll() {
        try {
            byte[] readBytes = new byte[available()];
            readFully(readBytes);
            return readBytes;
        } catch (IOException e) {
            throw new AssertionError();
        }
    }

    public int readInteger() {
        try {
            return readInt();
        } catch (IOException e) {
            throw new AssertionError();
        }
    }

    public byte readSigned() {
        try {
            return readByte();
        } catch (IOException e) {
            throw new AssertionError();
        }
    }

    public int readUnsigned() {
        try {
            return readUnsignedByte();
        } catch (IOException e) {
            throw new AssertionError();
        }
    }
}
