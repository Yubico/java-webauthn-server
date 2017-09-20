package demo.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.util.WebAuthnCodecs;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scala.collection.immutable.Vector;

public class InMemoryCredentialRepository implements CredentialRepository {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryCredentialRepository.class);

    private final Map<String, JsonNode> keyStorage = new HashMap<>();

    @Override
    public Optional<PublicKey> lookup(String credentialId) {
        JsonNode cose = keyStorage.get(credentialId);
        if (cose == null) {
            return Optional.empty();
        } else {
            PublicKey key = WebAuthnCodecs.importCoseP256PublicKey(cose);
            if (key == null) {
                logger.error("Failed to decode public key in storage: {}", credentialId);
            }
            return Optional.ofNullable(key);
        }
    }

    @Override
    public Optional<PublicKey> lookup(Vector<Object> rawId) {
        return Optional.empty();
    }

    public void add(String keyId, JsonNode key) {
        keyStorage.put(keyId, key);
    }

}
