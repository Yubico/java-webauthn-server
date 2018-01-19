(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['base64url'], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('base64url'));
  } else {
    root.webauthn = factory(root.base64url);
  }
})(this, function(base64url) {

  const browserFixes = function() {
    const fixes = [
      {
        name: 'Firefox 57',
        isEnabled() {
          return typeof InstallTrigger !== undefined && window.navigator.userAgent.match(/Firefox\/57/);
        },
        fixRegisterRequest(makePublicKeyCredentialOptions) {
          return {
            ...makePublicKeyCredentialOptions,
            excludeList: makePublicKeyCredentialOptions.excludeCredentials,
            parameters: makePublicKeyCredentialOptions.pubKeyCredParams,
          }
        },
        fixAuthenticateRequest(publicKeyCredentialRequestOptions) {
          return {
            ...publicKeyCredentialRequestOptions,
            allowList: publicKeyCredentialRequestOptions.allowCredentials,
          };
        },
      },
    ];

    return {
      fixRegisterRequest(mpkco) {
        return fixes.reduce(
          (result, fix) => {
            if (fix.isEnabled()) {
              return fix.fixRegisterRequest(result);
            } else {
              return result;
            }
          },
          mpkco
        );
      },

      fixAuthenticateRequest(pkcro) {
        return fixes.reduce(
          (result, fix) => {
            if (fix.isEnabled()) {
              return fix.fixAuthenticateRequest(result);
            } else {
              return result;
            }
          },
          pkcro
        );
      },
    };
  }();

  /**
   * Add Jackson JSON deserialization type hints to a PublicKeyCredential-like
   * plain object structure.
   */
  function addJacksonDeserializationHints(response) {
    const root = {
      ...response,
      '@jackson_type': 'com.yubico.webauthn.data.impl.PublicKeyCredential',
    };

    if (response.response.attestationObject) {
      return {
        ...root,
        response: {
          ...response.response,
          '@jackson_type': 'com.yubico.webauthn.data.impl.AuthenticatorAttestationResponse',
        },
      };
    } else {
      return {
        ...root,
        response: {
          ...response.response,
          '@jackson_type': 'com.yubico.webauthn.data.impl.AuthenticatorAssertionResponse',
        },
      };
    }
  }

  /**
   * Create a WebAuthn credential.
   *
   * @param request: object - A MakePublicKeyCredentialOptions object, except
   *   where binary values are base64url encoded strings instead of byte arrays
   *
   * @return a MakePublicKeyCredentialOptions suitable for passing as the
   *   `publicKey` parameter to `navigator.credentials.create()`
   */
  function decodeMakePublicKeyCredentialOptions(request) {
    const excludeCredentials = request.excludeCredentials.map(credential => ({
      ...credential,
      id: base64url.toByteArray(credential.id),
    }));

    const makePublicKeyCredentialOptions = {
      ...request,
      user: {
        ...request.user,
        id: base64url.toByteArray(request.user.id),
      },
      challenge: base64url.toByteArray(request.challenge),
      excludeCredentials,
      timeout: 10000,
    };

    return browserFixes.fixRegisterRequest(makePublicKeyCredentialOptions);
  }

  /**
   * Create a WebAuthn credential.
   *
   * @param request: object - A MakePublicKeyCredentialOptions object, except
   *   where binary values are base64url encoded strings instead of byte arrays
   *
   * @return the Promise returned by `navigator.credentials.create`
   */
  function createCredential(request) {
    return navigator.credentials.create({
      publicKey: decodeMakePublicKeyCredentialOptions(request),
    });
  }

  /**
   * Perform a WebAuthn assertion.
   *
   * @param request: object - A PublicKeyCredentialRequestOptions object,
   *   except where binary values are base64url encoded strings instead of byte
   *   arrays
   *
   * @return a PublicKeyCredentialRequestOptions suitable for passing as the
   *   `publicKey` parameter to `navigator.credentials.get()`
   */
  function decodePublicKeyCredentialRequestOptions(request) {
    const allowCredentials = request.allowCredentials.map(credential => ({
      ...credential,
      id: base64url.toByteArray(credential.id),
    }));

    const publicKeyCredentialRequestOptions = {
      ...request,
      allowCredentials: allowCredentials,
      challenge: base64url.toByteArray(request.challenge),
      timeout: 10000,
    };

    return browserFixes.fixAuthenticateRequest(publicKeyCredentialRequestOptions);
  }

  /**
   * Perform a WebAuthn assertion.
   *
   * @param request: object - A PublicKeyCredentialRequestOptions object,
   *   except where binary values are base64url encoded strings instead of byte
   *   arrays
   *
   * @return the Promise returned by `navigator.credentials.get`
   */
  function getAssertion(request) {
    console.log('Get assertion', request);
    return navigator.credentials.get({
      publicKey: decodePublicKeyCredentialRequestOptions(request),
    });
  }


  /** Turn a PublicKeyCredential object into a plain object with base64url encoded binary values */
  function responseToObject(response) {
    if (response instanceof PublicKeyCredential) {
      if (response.response instanceof AuthenticatorAttestationResponse) {
        return {
          id: response.id,
          response: {
            attestationObject: base64url.fromByteArray(response.response.attestationObject),
            clientDataJSON: base64url.fromByteArray(response.response.clientDataJSON),
          },
        };
      } else if (response.response instanceof AuthenticatorAssertionResponse) {
        return {
          id: response.id,
          response: {
            authenticatorData: base64url.fromByteArray(response.response.authenticatorData),
            clientDataJSON: base64url.fromByteArray(response.response.clientDataJSON),
            signature: base64url.fromByteArray(response.response.signature),
          },
        };
      } else {
        throw new Error("Argument.response must be an AuthenticatorAttestationResponse or AuthenticatorAssertionResponse, was: " + (typeof response.response));
      }
    } else {
      throw new Error("Argument must be a PublicKeyCredential, was: " + (typeof response));
    }
  }

  return {
    addJacksonDeserializationHints,
    decodeMakePublicKeyCredentialOptions,
    decodePublicKeyCredentialRequestOptions,
    createCredential,
    getAssertion,
    responseToObject,
  };

});
