<#-- @ftlvariable name="" type="demo.HtmlView" -->
<html>
<head>
<title>Java U2F Demo</title>

<script src="chrome-extension://pfboblefjcgdjicmnffhdgionmgcdmne/u2f-api.js"></script>

<script>
var request = ${data};
var signs = [];
setTimeout(function() {
    <#if method == "Registration">
        u2f.register([request], signs,
    <#else>
        u2f.sign([request],
    </#if>
    function(data) {
        var form = document.getElementById('form');
        var reg = document.getElementById('tokenResponse');
        if(data.errorCode) {
            alert("U2F failed with error: " + data.errorCode);
            return;
        }
        reg.value=JSON.stringify(data);
        form.submit();
    });
}, 1000);
</script>

</head>
    <body>
    <p>Enter a username and then touch your U2F token.</p>
        <form method="POST" action="finish${method}" id="form">
            <label for="username">Username</label>
            <input name="username" id="username" autofocus />
            <input type="hidden" name="tokenResponse" id="tokenResponse"/>
        </form>
    </body>
</html>
