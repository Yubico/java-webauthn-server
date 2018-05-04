(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['base64url'], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('base64url'));
  } else {
    root.webauthn = factory(root.base64url);
  }
})(this, function(base64url) {

  function extend(obj, more) {
    return Object.assign({}, obj, more);
  }

  const browserFixes = function() {
    const fixes = [
      {
        name: 'Firefox 57',
        isEnabled() {
          return typeof InstallTrigger !== undefined && window.navigator.userAgent.match(/Firefox\/57/);
        },
        fixRegisterRequest(publicKeyCredentialCreationOptions) {
          return extend(
            publicKeyCredentialCreationOptions, {
            excludeList: publicKeyCredentialCreationOptions.excludeCredentials,
            parameters: publicKeyCredentialCreationOptions.pubKeyCredParams,
          });
        },
        fixAuthenticateRequest(publicKeyCredentialRequestOptions) {
          return extend(
            publicKeyCredentialRequestOptions, {
            allowList: publicKeyCredentialRequestOptions.allowCredentials,
          });
        },
      },
    ];

    function applyFixes(fixName, arg) {
      return fixes.reduce(
        (result, fix) => {
          if (fix.isEnabled()) {
            return fix[fixName](result);
          } else {
            return result;
          }
        },
        arg
      );
    }

    return {
      fixRegisterRequest(mpkco) {
        return applyFixes('fixRegisterRequest', mpkco);
      },

      fixAuthenticateRequest(pkcro) {
        return applyFixes('fixAuthenticateRequest', pkcro);
      },
    };
  }();

  /**
   * Create a WebAuthn credential.
   *
   * @param request: object - A PublicKeyCredentialCreationOptions object, except
   *   where binary values are base64url encoded strings instead of byte arrays
   *
   * @return a PublicKeyCredentialCreationOptions suitable for passing as the
   *   `publicKey` parameter to `navigator.credentials.create()`
   */
  function decodePublicKeyCredentialCreationOptions(request) {
    const excludeCredentials = request.excludeCredentials.map(credential => extend(
      credential, {
      id: base64url.toByteArray(credential.id),
    }));

    const publicKeyCredentialCreationOptions = extend(
      request, {
      attestation: 'direct',
      user: extend(
        request.user, {
        id: base64url.toByteArray(request.user.id),
      }),
      challenge: base64url.toByteArray(request.challenge),
      excludeCredentials,
      timeout: 10000,
    });

    return browserFixes.fixRegisterRequest(publicKeyCredentialCreationOptions);
  }

  /**
   * Create a WebAuthn credential.
   *
   * @param request: object - A PublicKeyCredentialCreationOptions object, except
   *   where binary values are base64url encoded strings instead of byte arrays
   *
   * @return the Promise returned by `navigator.credentials.create`
   */
  function createCredential(request) {
    return navigator.credentials.create({
      publicKey: decodePublicKeyCredentialCreationOptions(request),
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
    const allowCredentials = request.allowCredentials && request.allowCredentials.map(credential => extend(
      credential, {
      id: base64url.toByteArray(credential.id),
    }));

    const publicKeyCredentialRequestOptions = extend(
      request, {
      allowCredentials,
      challenge: base64url.toByteArray(request.challenge),
      timeout: 10000,
    });

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
    if (response.response.attestationObject) {
      return {
        id: response.id,
        response: {
          attestationObject: base64url.fromByteArray(response.response.attestationObject),
          clientDataJSON: base64url.fromByteArray(response.response.clientDataJSON),
        },
      };
    } else {
      return {
        id: response.id,
        response: {
          authenticatorData: base64url.fromByteArray(response.response.authenticatorData),
          clientDataJSON: base64url.fromByteArray(response.response.clientDataJSON),
          signature: base64url.fromByteArray(response.response.signature),
        },
      };
    }
  }

  return {
    decodePublicKeyCredentialCreationOptions,
    decodePublicKeyCredentialRequestOptions,
    createCredential,
    getAssertion,
    responseToObject,
  };

});
