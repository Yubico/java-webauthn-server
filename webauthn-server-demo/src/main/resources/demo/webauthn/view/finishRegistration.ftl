<html>
<head>
<meta charset="utf-8"/>
<title>Java WebAuthn Demo</title>

<script>

window.onload = function() {
  document.getElementById("request").innerHTML = JSON.stringify(${requestJson}, false, 2);
  document.getElementById("response").innerHTML = JSON.stringify(${responseJson}, false, 2);
}
</script>

</head>
<body>

    <p>Successfully registered credential:</p>

    <table>
      <tbody>
        <tr><th>Username:</th> <td> ${registration.getUsername()}</td></tr>
        <tr><th>Registration time:</th> <td> <pre>${registration.getRegistrationTime()}</pre></td></tr>
        <tr><th>Credential nickname:</th> <td> <pre>${registration.getCredentialNickname()}</pre></td></tr>
        <tr><th>Key ID:</th> <td> <pre>${registration.getRegistration().keyId().idBase64()}</pre></td></tr>
        <tr><th>Public key:</th> <td> <pre>${response.getCredential().response().attestation().authenticatorData().attestationData().get().credentialPublicKey().toString()}</pre></td></tr>
        <tr><th>Attestation type:</th> <td> <b>${registration.getRegistration().attestationType().name()}</b></td></tr>
        <tr><th>Attestation trusted:</th> <td> <b>${registration.getRegistration().attestationTrusted() ?c}</b></td></tr>
      </tbody>
    </table>

    <#if registration.getRegistration().attestationMetadata().isPresent()>
      <h3>Attestation metadata:</h3>

      <p> Identifier: ${registration.getRegistration().attestationMetadata().get().getMetadataIdentifier()} </p>

      <#list registration.getRegistration().attestationMetadata().get().getVendorProperties()>
        <p>Vendor metadata</p>

        <#items as key, value>
            <pre>${key}: ${value}</pre>
        </#items>
      <#else>
          <p>No vendor metadata present!</p>
      </#list>

      <#list registration.getRegistration().attestationMetadata().get().getDeviceProperties()>
          <p>Device metadata</p>

          <#items as key, value>
              <pre>${key}: ${value}</pre>
          </#items>
      <#else>
          <p>No device metadata present!</p>
      </#list>

      <#list registration.getRegistration().attestationMetadata().get().getTransports()>
          <p>Transports:</p>

          <#items as item>
            <pre>${item}</pre>
          </#items>
      <#else>
          <p>No transports metadata present!</p>
      </#list>

    <#else>
      <p>No attestation metadata found.</p>
    </#if>

    <h3> Request </h3>
    <pre id="request">${requestJson}</pre>

    <h3> Response </h3>
    <p>Properties prefixed with <code>_</code> are parsed versions of the corresponding Base64 encoded binary blob.
    Properties prefixed with <code>@</code> are implementation-specific deserialization hints.</p>
    <pre id="response">${responseJson}</pre>

    <#include "/demo/view/navigation.ftl">

</body>
</html>
