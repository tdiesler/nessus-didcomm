<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8"/>
        <title>Nessus Identity</title>
        <style>
            body { font-family: sans-serif; padding: 2em; background-color: #f9f9f9; }
            h1 { color: #333; font-size: 1.2em; }
            p { font-size: 1.0em; }
        </style>
    </head>
    <body>
        <h1>EBSI OpenID4VC and Wallet Proxy</h1>

        <#if walletName??>
            <p>
                ${walletName}
                <table>
                    <tr>
                        <td>Subject Did</td>
                        <td><input type="text" value="${did!}" size="80" readonly/></td>
                    </tr>
                    <tr>
                        <td>Holder Endpoint</td>
                        <td><input type="text" value="${holderUri}" size="80" readonly/>&nbsp;<a style="font-size: small;" href="/logout">logout</a></td>
                    </tr>
                </table>
            </p>
        <#else>
            <form id="loginForm" method="post" action="/login">
                <table>
                    <tr>
                        <td><label for="email">Email:</label></td>
                        <td><input type="email" id="email" name="email" value="user@email.com" required /></td>
                    </tr>
                    <tr>
                        <td><label for="password">Password:</label></td>
                        <td><input type="password" id="password" name="password" value="password" required /></td>
                        <td><a style="font-size: small;" href="#" onclick="document.getElementById('loginForm').submit(); return false;">login</a></td>
                    </tr>
                </table>
            </form>
        </#if>

        <hr/>

        Learn about EBSI
        <ul>
            <li><a href="https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows">Issue Credentials</a></li>
            <li><a href="https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows">Hold Credentials</a></li>
            <li><a href="https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows">Verify Credentials</a></li>
        </ul>

        EBSI Conformance Tests
        <ul>
            <li><a href="https://hub.ebsi.eu/wallet-conformance/issue-to-holder">Issue Credentials</a></li>
            <li><a href="https://hub.ebsi.eu/wallet-conformance/holder-wallet">Hold Credentials</a></li>
            <li><a href="https://hub.ebsi.eu/wallet-conformance/verifier">Verify Credentials</a></li>
        </ul>

        View Metadata
        <p>
            <table>
                <tr>
                    <td>EBSI</td>
                    <td><a href="https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/.well-known/openid-credential-issuer">Issuer</a></td>
                    <td><a href="https://api-conformance.ebsi.eu/conformance/v3/auth-mock/.well-known/openid-configuration">OAuth</a></td>
                </tr>
                <tr>
                    <td>Nessus</td>
                    <td><a href="/issuer/.well-known/openid-credential-issuer">Issuer</a></td>
                    <td><a href="/oauth/.well-known/openid-configuration">OAuth</a></td>
                </tr>
            </table>
        </p>

        Service
        <ul>
            <li><a href="${demoWalletUrl}">Demo Wallet</a></li>
        </ul>
    </body>
</html>
