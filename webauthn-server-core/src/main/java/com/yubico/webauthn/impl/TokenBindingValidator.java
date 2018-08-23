package com.yubico.webauthn.impl;

import com.yubico.util.ByteArray;
import com.yubico.webauthn.data.TokenBindingInfo;
import java.util.Optional;


public class TokenBindingValidator {

    public static boolean validate(Optional<TokenBindingInfo> clientTokenBinding, Optional<ByteArray> rpTokenBindingId) {
        return rpTokenBindingId.map(rpToken ->
            clientTokenBinding.map(tbi -> {
                switch (tbi.getStatus()) {
                    case SUPPORTED:
                    case NOT_SUPPORTED:
                        throw new IllegalArgumentException("Token binding ID set by RP but not by client.");

                    case PRESENT:
                        return tbi.getId().map(id -> {
                            if (id.equals(rpToken)) {
                                return true;
                            } else {
                                throw new IllegalArgumentException("Incorrect token binding ID.");
                            }
                        }).orElseThrow(() -> new IllegalArgumentException("Property \"id\" missing from \"tokenBinding\" object."));
                }
                throw new RuntimeException("Unknown token binding status: " + tbi.getStatus());
            }).orElseThrow(() -> new IllegalArgumentException("Token binding ID set by RP but not by client."))
        ).orElseGet(() ->
            clientTokenBinding.map(tbi -> {
                switch (tbi.getStatus()) {
                    case SUPPORTED:
                    case NOT_SUPPORTED:
                        return true;

                    case PRESENT:
                        throw new IllegalArgumentException("Token binding ID set by client but not by RP.");
                }
                throw new RuntimeException("Unknown token binding status: " + tbi.getStatus());
            }).orElse(true)
        );
    }

}
