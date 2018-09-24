package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * The attributes that are specified by a caller when referring to a credential as an input parameter to the create() or
 * get() methods. It mirrors the fields of the [[PublicKeyCredential]] object returned by the latter methods.
 */
@Value
@Builder
public class PublicKeyCredentialDescriptor implements Comparable<PublicKeyCredentialDescriptor> {

    /**
     * The type of the credential the caller is referring to.
     */
    @NonNull
    @Builder.Default
    private final PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;

    /**
     * The identifier of the credential that the caller is referring to.
     */
    @NonNull
    private final ByteArray id;

    @NonNull
    @Builder.Default
    private final Optional<Set<AuthenticatorTransport>> transports = Optional.empty();

    public PublicKeyCredentialDescriptor(
        @NonNull PublicKeyCredentialType type,
        @NonNull ByteArray id,
        @NonNull Optional<Set<AuthenticatorTransport>> transports
    ) {
        this.type = type;
        this.id = id;
        this.transports = transports.map(TreeSet::new).map(Collections::unmodifiableSortedSet);
    }

    @JsonCreator
    private PublicKeyCredentialDescriptor(
        @NonNull @JsonProperty("type") PublicKeyCredentialType type,
        @NonNull @JsonProperty("id") ByteArray id,
        @JsonProperty("transports") Set<AuthenticatorTransport> transports
    ) {
        this(type, id, Optional.ofNullable(transports));
    }

    @Override
    public int compareTo(PublicKeyCredentialDescriptor other) {
        int idComparison = id.compareTo(other.id);
        if (idComparison != 0) {
            return idComparison;
        }

        if (type.compareTo(other.type) != 0) {
            return type.compareTo(other.type);
        }

        return hashCode() - other.hashCode();
    }
}
