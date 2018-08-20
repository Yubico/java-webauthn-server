package com.yubico.webauthn.meta;

import java.net.URL;
import java.util.Optional;
import lombok.Value;


/**
 * Description of this version of this library
 */
@Value
public class Implementation {

    /**
     * The version number of this release of the library.
     */
    private final Optional<String> version;

    /**
     * Address to where the source code for this library can be found.
     */
    private final URL sourceCodeUrl;

}
