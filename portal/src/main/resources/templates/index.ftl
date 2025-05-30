<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8"/>
        <title>Nessus Identity</title>
        <style>
            body { font-family: sans-serif; background-color: #f9f9f9; }
            .code-block {
                background-color: #f0f0f0;
                padding: 0.2em;
                font-family: monospace;
                white-space: pre;
                overflow-x: auto;
                display: none;
            }
        </style>
        <script>
            function toggleCode() {
                const block = document.getElementById("jsonBlock");
                const isHidden = getComputedStyle(block).display === "none";
                block.style.display = isHidden ? "block" : "none";
            }
        </script>
    </head>
    <body>
        <h3>Nessus Identity - EBSI Conformance Portal</h3>

        <#if hasWalletId>
            <p/>
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
            <#if !did??>
                <p/>
                Please create did:key:jwk_jcs-pub identifier from ECDSA_Secp256r1 key algorithm in the <a href="${devWalletUrl}" target="_blank">Dev Wallet</a><br/>
                i.e. first create a private key with that algirithm, then a 'did:key:...' from that private key. Then <a href="/logout">logout</a> and login again.
            </#if>
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
                        <td>
                            <a style="font-size: small;" href="#" onclick="document.getElementById('loginForm').submit(); return false;">login</a>
                            <a style="font-size: small;" href="${demoWalletUrl}" target="_blank">register</a>
                        </td>
                    </tr>
                </table>
            </form>
        </#if>

        <hr/> <!-------------------------------------------------------------------------------------------------------->

        <h3>Learn about EBSI</h3>
        <ul>
            <li><a href="https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows">Issue Credentials</a></li>
            <li><a href="https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows">Hold Credentials</a></li>
            <li><a href="https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows">Verify Credentials</a></li>
        </ul>

        <#if hasWalletId>

            <h3>View Metadata</h3>
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

            <h3>Service</h3>
            <ul>
                <li><a href="${demoWalletUrl}" target="_blank">Demo Wallet</a></li>
                <li><a href="${devWalletUrl}" target="_blank">Dev Wallet</a></li>
            </ul>

            <hr/> <!-------------------------------------------------------------------------------------------------------->

            <h3>EBSI Conformance Tests</h3>

            <h4>Request and present Verifiable Credentials</h4>

                The Holder Wallet module checks the wallet's ability to handle credential requests, authentication and presentation to verifiers on demand.

                <p/>
                Go to the <a href="https://hub.ebsi.eu/wallet-conformance/holder-wallet" target="_blank">start tests</a> page for holder wallets and
                <i>Insert your DID</i> and <i>Credential Offer Endpoint</i> from above. Then use "No" for QR code reading capabilities.
                To run the first test, pull down <i>In-time Credential</i> and click <i>Initiate (credential offering redirect)</i>

                <p/>
                If all goes well, the browser should <button onclick="toggleCode()">show</button> the credential that ebsi has just issued.
                It should also show up in your <a href="${demoWalletUrl}" target="_blank">wallet</a>.
<pre id="jsonBlock" class="code-block"><code>
{
    "sub": "${did}",
    "nbf": 1748613301,
    "iss": "did:ebsi:zjHZjJ4Sy7r92BxXzFGs7qD",
    "exp": 1748699706,
    "iat": 1748613301,
    "vc": {
        "@context": [ "https://www.w3.org/2018/credentials/v1" ],
        "credentialSchema": {
            "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
            "type": "FullJsonSchemaValidator2021"
        },
        "credentialSubject": {
            "id": "${did}"
        },
        "expirationDate": "2025-05-31T13:55:06Z",
        "id": "vc:ebsi:conformance#6bbeae8a-a7f5-41a7-949a-8c675a1262ef",
        "issuanceDate": "2025-05-30T13:55:01Z",
        "issued": "2025-05-30T13:55:01Z",
        "issuer": "did:ebsi:zjHZjJ4Sy7r92BxXzFGs7qD",
        "type": [
            "VerifiableCredential",
            "VerifiableAttestation",
            "CTWalletSameAuthorisedInTime"
        ],
        "validFrom": "2025-05-30T13:55:01Z",
        "termsOfUse": {
            "id": "https://api-conformance.ebsi.eu/trusted-issuers-registry/v5/issuers/did:ebsi:zjHZjJ4Sy7r92BxXzFGs7qD/attributes/bcdb6bc952c8c897ca1e605fce25f82604c76c16d479770014b7b262b93c0250",
            "type": "IssuanceCertificate"
        }
    },
    "jti": "vc:ebsi:conformance#6bbeae8a-a7f5-41a7-949a-8c675a1262ef"
}
</code></pre>

        </#if>

    </body>
</html>
