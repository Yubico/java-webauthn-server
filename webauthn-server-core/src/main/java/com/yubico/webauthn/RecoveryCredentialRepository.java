package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.RecoveryCredential;
import com.yubico.webauthn.data.RecoveryCredentialsState;
import java.util.Optional;
import java.util.Set;

public interface RecoveryCredentialRepository {

    Set<RecoveryCredentialsState> lookupRecoveryStates(ByteArray userHandle);

    default RecoveryCredentialsState lookupRecoveryState(ByteArray mainCredentialId, ByteArray userHandle) {
        return lookupRecoveryStates(userHandle)
            .stream()
            .filter(state -> state.getMainCredentialId().equals(mainCredentialId))
            .findAny()
            .orElseGet(() -> RecoveryCredentialsState.initial(mainCredentialId));
    }

    default Optional<RecoveryCredential> lookupRecoveryCredential(ByteArray recoveryCredentialId, ByteArray userHandle) {
        return lookupRecoveryStates(userHandle)
            .stream()
            .flatMap(state -> state.getRecoveryCredentials().stream())
            .filter(recoveryCredential -> recoveryCredential.getCredentialId().equals(recoveryCredentialId))
            .findAny();
    }

}
