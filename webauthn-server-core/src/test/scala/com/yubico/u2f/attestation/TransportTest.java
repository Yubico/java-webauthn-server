package com.yubico.u2f.attestation;

import java.util.EnumSet;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Created by Dain on 2016-02-18.
 */
public class TransportTest {

    @Test
    public void testParsingSingleValuesFromInt() {
        assertEquals(EnumSet.of(Transport.BT_CLASSIC), Transport.fromInt(1));
        assertEquals(EnumSet.of(Transport.BLE), Transport.fromInt(2));
        assertEquals(EnumSet.of(Transport.USB), Transport.fromInt(4));
        assertEquals(EnumSet.of(Transport.NFC), Transport.fromInt(8));
    }

    @Test
    public void testParsingSetsFromInt() {
        assertEquals(EnumSet.noneOf(Transport.class), Transport.fromInt(0));
        assertEquals(EnumSet.of(Transport.BLE, Transport.NFC), Transport.fromInt(10));
        assertEquals(EnumSet.of(Transport.USB, Transport.BT_CLASSIC), Transport.fromInt(5));
        assertEquals(EnumSet.of(Transport.BT_CLASSIC, Transport.BLE, Transport.USB, Transport.NFC),
                Transport.fromInt(15));
    }

    @Test
    public void testEncodingSingleValuesToInt() {
        assertEquals(1, Transport.toInt(Transport.BT_CLASSIC));
        assertEquals(2, Transport.toInt(Transport.BLE));
        assertEquals(4, Transport.toInt(Transport.USB));
        assertEquals(8, Transport.toInt(Transport.NFC));
    }

    @Test
    public void testEncodingSetsToInt() {
        assertEquals(0, Transport.toInt());
        assertEquals(10, Transport.toInt(Transport.BLE, Transport.NFC));
        assertEquals(5, Transport.toInt(Transport.USB, Transport.BT_CLASSIC));
        assertEquals(15, Transport.toInt(Transport.BT_CLASSIC, Transport.BLE, Transport.USB, Transport.NFC));
    }

}
