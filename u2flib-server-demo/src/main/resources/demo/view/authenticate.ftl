<html>
<head>
<title>Java U2F Demo</title>

<script src="/assets/u2f-api.js"></script>

<script>
var request = ${data};
setTimeout(function() {
    u2f.sign(request.authenticateRequests,
    function(data) {
        if(data.errorCode) {
            alert("U2F failed with error code: " + data.errorCode);
            return;
        }
        document.getElementById('tokenResponse').value = JSON.stringify(data);
        document.getElementById('form').submit();
    });
}, 1000);
</script>

</head>
    <body>
    <p>Touch your U2F token to authenticate.</p>
        <form method="POST" action="finishAuthentication" id="form">
            <input type="hidden" name="tokenResponse" id="tokenResponse"/>
            <input type="hidden" name="username" id="username" value="${username}"/>
        </form>
    </body>
</html>
