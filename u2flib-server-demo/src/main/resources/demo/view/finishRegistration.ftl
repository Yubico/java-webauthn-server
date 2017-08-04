<html>
<head>
<title>Java U2F Demo</title>
</head>
<body>

    <p>Successfully registered device:</p>

    <#list attestation.getVendorProperties()>
        <p>Vendor metadata</p>

        <#items as key, value>
            <pre>
                ${key}: ${value}
            </pre>
        </#items>
    <#else>
        <p>No vendor metadata present!</p>
    </#list>

    <#list attestation.getDeviceProperties()>
        <p>Device metadata</p>

        <#items as key, value>
            <pre>
                ${key}: ${value}
            </pre>
        </#items>
    <#else>
        <p>No device metadata present!</p>
    </#list>

    <#list attestation.getTransports()>
        <p>Device transports: <#items as item>${item}<#sep>, </#sep></#items></p>
    <#else>
        <p>No device transports reported!</p>
    </#list>

    <p>Registration data</p>
    <pre> ${registration} </pre>

    <#include "navigation.ftl">

</body>
</html>
