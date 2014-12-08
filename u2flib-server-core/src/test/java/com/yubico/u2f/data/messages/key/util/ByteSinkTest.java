package com.yubico.u2f.data.messages.key.util;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.InputMismatchException;

import static org.junit.Assert.*;

public class ByteSinkTest {

    @Test
    public void putUnsignedIntShouldHandleBigValues() throws Exception {
        long bigValue = ((long) Integer.MAX_VALUE) + 1;

        byte[] result = ByteSink.create()
                .putUnsignedInt(bigValue)
                .toByteArray();

        byte[] expected = new byte[] {-0x80, 0x0, 0x0, 0x0}; // 0b10000000_00000000_00000000_00000000

        assertArrayEquals(expected, result);
    }

    @Test
    public void putUnsignedIntShouldExtendWriteInt() throws Exception {
        for(int i=0; i<Integer.MAX_VALUE && i>=0; i+=123456) {
            byte[] result = ByteSink.create()
                    .putUnsignedInt(i)
                    .toByteArray();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeInt(i);
            dos.flush();
            byte[] expected = baos.toByteArray();

            assertArrayEquals(expected, result);
        }
    }
}