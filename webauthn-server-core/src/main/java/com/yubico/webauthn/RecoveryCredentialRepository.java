package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.RecoveryCredential;
import com.yubico.webauthn.data.RecoveryCredentialsState;
import java.util.Map;
import java.util.Optional;

public interface RecoveryCredentialRepository {

    Map<ByteArray, RecoveryCredentialsState> lookupRecoveryStates(ByteArray userHandle);

    default RecoveryCredentialsState lookupRecoveryState(ByteArray mainCredentialId, ByteArray userHandle) {
        return Optional.ofNullable(lookupRecoveryStates(userHandle)
            .get(mainCredentialId))
            .orElseGet(() -> RecoveryCredentialsState.initial(mainCredentialId));
    }

    default Optional<RecoveryCredential> lookupRecoveryCredential(ByteArray recoveryCredentialId, ByteArray userHandle) {
        return lookupRecoveryStates(userHandle)
            .values()
            .stream()
            .flatMap(state -> state.getRecoveryCredentials().stream())
            .filter(recoveryCredential -> recoveryCredential.getCredentialId().equals(recoveryCredentialId))
            .findAny();
    }

}
