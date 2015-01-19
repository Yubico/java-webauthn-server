package com.yubico.u2f.data.messages.json;

import java.io.Serializable;

public interface Persistable extends Serializable {
    public String getRequestId();
    public String toJson();
}
