package com.yubico.u2f.data.messages.json;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.io.Serializable;

public interface Persistable extends Serializable {
    @JsonIgnore
    public String getRequestId();

    public String toJson();
}
