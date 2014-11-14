package com.yubico.u2f.data.messages.json;

import com.yubico.u2f.exceptions.U2fException;

/**
 * Created by dain on 11/14/14.
 */
public interface Persistable {
    public String getKey() throws U2fException;
    public String toJson();
}
