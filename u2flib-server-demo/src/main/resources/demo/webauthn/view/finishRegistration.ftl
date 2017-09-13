<html>
<head>
<meta charset="utf-8"/>
<title>Java WebAuthn Demo</title>

<script>

window.onload = function() {
  document.getElementById("request").innerHTML = JSON.stringify(${requestJson}, false, 2);
}
</script>

</head>
<body>

    <p>Successfully registered credential:</p>

    <p>Username: ${registration.getUsername()}</p>
    <p>Key ID: <pre>${registration.getRegistration().keyId().idBase64()}</pre></p>
    <p>Public key: <pre>${response.getCredential().response().attestation().authenticatorData().attestationData().get().credentialPublicKey().toString()}</pre></p>
    <p>Attestation type: <b>${registration.getRegistration().attestationType().name()}</b></p>
    <p>Attestation trusted: <b>${registration.getRegistration().attestationTrusted() ?c}</b></p>

    <#if registration.getRegistration().attestationMetadata().isPresent()>
      <h3>Attestation metadata:</h3>

      <p> Identifier: ${registration.getRegistration().attestationMetadata().getIdentifier()} </p>
      <p> Version: ${registration.getRegistration().attestationMetadata().getVersion()} </p>

      <#list registration.getRegistration().attestationMetadata().get().getVendorInfo()>
        <p>Vendor metadata</p>

        <#items as key, value>
            <pre>
                ${key}: ${value}
            </pre>
        </#items>
      <#else>
          <p>No vendor metadata present!</p>
      </#list>

      <#list registration.getRegistration().attestationMetadata().get().getDevices()>
          <p>Device metadata</p>

          <#items as key, value>
              <pre>
                  ${key}: ${value}
              </pre>
          </#items>
      <#else>
          <p>No device metadata present!</p>
      </#list>

      <#list registration.getRegistration().attestationMetadata().get().getTrustedCertificates()>
          <p>Trusted certificates:</p>

          <#items as item>
            <pre>${item}</pre>
          </#items>
      <#else>
          <p>No trusted certificates given!</p>
      </#list>

    <#else>
      <p>No attestation metadata found.</p>
    </#if>

    <h3> Authenticator request </h3>
    <pre id="request">${requestJson}</pre>

    <#include "/demo/view/navigation.ftl">

</body>
</html>
