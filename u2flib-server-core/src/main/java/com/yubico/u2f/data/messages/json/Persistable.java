package com.yubico.u2f.data.messages.json;

import com.yubico.u2f.exceptions.U2fException;

public interface Persistable {
    public String getKey() throws U2fException;
    public String toJson();
}
