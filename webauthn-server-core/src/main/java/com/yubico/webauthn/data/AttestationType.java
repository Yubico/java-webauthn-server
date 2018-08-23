package com.yubico.webauthn.data;


public enum AttestationType {
    BASIC, // name: "Basic"
    SELF_ATTESTATION, // name: "Self attestation"
    PRIVACY_CA, // name: "Privacy CA"
    ECDAA, // name: "ECDAA"
    NONE; // name: "None"
}
