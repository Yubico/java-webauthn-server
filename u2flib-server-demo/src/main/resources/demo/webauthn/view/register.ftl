<html>
<head>
<meta charset="utf-8"/>

<title>Java WebAuthn Demo</title>

<script src="/lib/base64js/base64js-1.2.0.min.js"></script>
<script src="/js/base64url.js"></script>
<script src="/js/webauthn.js"></script>

<script>

function translateForFirefoxNightly57_0a1(request) {
  return Object.assign({}, request, {
    parameters: request.parameters.map(function(item) {
      return Object.assign({}, item, {
        algorithm: item.alg === -7 ? 'ES256' : item.alg,
      });
    }),
  });
}

function submitResponse(requestId, response) {
  var form = document.getElementById('form');
  var responseField = document.getElementById('response');
  responseField.value = JSON.stringify({
    requestId: requestId,
    credential: webauthn.addJacksonDeserializationHints(webauthn.responseToObject(response)),
  });
  form.submit();
}

window.onload = function() {
  var request = ${requestJson};
  console.log('onload', request);
  document.getElementById("request").innerHTML = JSON.stringify(request, false, 2);

  webauthn.createCredential(translateForFirefoxNightly57_0a1(request.makePublicKeyCredentialOptions))
    .then(function(response) {
      console.log('Response:', response);
      console.log('Response:', JSON.stringify(webauthn.responseToObject(response)));
      window.result = response;
      return response;
    }).then(function(response) {
      submitResponse("${requestId}", response);
    }).catch(function(err) {
      console.error('Failed:', err.name, err.message, err);

      if (err.name === 'NotAllowedError'
        && request.makePublicKeyCredentialOptions.excludeCredentials
        && request.makePublicKeyCredentialOptions.excludeCredentials.length > 0
      ) {
        document.getElementById('messages').innerHTML += '<p>Credential creation failed, probably because an already registered credential is avaiable.</p>';
      } else {
        document.getElementById('messages').innerHTML += '<p>Credential creation failed for an unknown reason.</p>';
      }
    })
  ;

  return false;
}

</script>

</head>
<body>

  <p>Requesting credential creation!</p>
  <p>Your browser or authenticator may prompt you for confirmation. If your authenticator is blinking, touch it now.</p>

  <form method="POST" action="finishRegistration" id="form" onsubmit="return false">
    <input type="hidden" name="response" id="response"/>
  </form>

  <div id="messages">
  </div>

  <p> Request ID: <pre>${requestId}</pre></p>

  <p> Request: </p>
  <pre id="request">${requestJson}</pre>

  <#include "/demo/view/navigation.ftl">

</body>
</html>
