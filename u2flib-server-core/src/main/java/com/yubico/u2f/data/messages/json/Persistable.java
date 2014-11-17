package com.yubico.u2f.data.messages.json;

import com.yubico.u2f.exceptions.U2fException;

import java.io.Serializable;

public interface Persistable extends Serializable {
    public String getKey() throws U2fException;
    public String toJson();
}
