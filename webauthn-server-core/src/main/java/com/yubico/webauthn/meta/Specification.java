package com.yubico.webauthn.meta;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.impl.json.LocalDateJsonSerializer;
import java.net.URL;
import java.time.LocalDate;
import lombok.Builder;
import lombok.Value;


/**
 * Reference to a particular version of a specification document.
 */
@Value
@Builder
public class Specification {

    /**
     * Address to this version of the specification.
     */
    private final URL url;

    /**
     * Address to the latest version of this specification.
     */
    private final URL latestVersionUrl;

    /**
     * An object indicating the status of the specification document.
     */
    private final DocumentStatus status;

    /**
     * The release date of the specification document.
     */
    @JsonSerialize(using = LocalDateJsonSerializer.class)
    private final LocalDate releaseDate;

}
