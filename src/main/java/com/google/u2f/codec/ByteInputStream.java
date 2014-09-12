package com.google.u2f.codec;

import com.google.u2f.U2fException;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

//  ByteArrayInputStream cannot throw IOExceptions, so this class is converting checked exceptions to unchecked.
public class ByteInputStream extends DataInputStream {

  ByteInputStream(byte[] data) {
    super(new ByteArrayInputStream(data));
  }

  byte[] read(int numberOfBytes) {
    byte[] readBytes = new byte[numberOfBytes];
    try {
      readFully(readBytes);
    } catch (IOException e) {
      throw new AssertionError();
    }
    return readBytes;
  }

  byte[] readAll() {
    try {
      byte[] readBytes = new byte[available()];
      readFully(readBytes);
      return readBytes;
    } catch (IOException e) {
      throw new AssertionError();
    }
  }

  int readInteger() {
    try {
      return readInt();
    } catch (IOException e) {
      throw new AssertionError();
    }
  }

  byte readSigned() {
    try {
      return readByte();
    } catch (IOException e) {
      throw new AssertionError();
    }
  }

  int readUnsigned() {
    try {
      return readUnsignedByte();
    } catch (IOException e) {
      throw new AssertionError();
    }
  }

  void checkIsExhausted() throws U2fException {
    try {
      if(available() != 0) {
        throw new U2fException("Message ends with unexpected data");
      }
    } catch (IOException e) {
      throw new AssertionError();
    }
  }
}
