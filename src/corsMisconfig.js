import { makeRequest } from "./requestHelper.js";

function generateTestURL(url) {
    const myURL1 = new URL(url);
    const myURL2 = new URL(url);

    const baseHostname = myURL2.hostname;

    const parts = myURL1.hostname.split('.');
    const tld = parts.pop();
    myURL1.hostname = `${parts.join('.')}.evil.${tld}`;

    myURL2.hostname = `evil-${baseHostname}`;

    return [
        { originHeader: myURL1.origin },
        { originHeader: myURL2.origin },
        { originHeader: 'null' }
    ];
}

export async function checkCorsMisconfig(url, pathMethod) {
    const endpointPromises = pathMethod.map(async (input) => {
        const endpointResults = [];
        let currentUrlString = `${url}/${input.path}`;

        try {
            const receivedUrl = new URL(input.path, url);
            currentUrlString = receivedUrl.href;
        } catch (error) {
            endpointResults.push({
                    checkName: 'CORS Misconfiguration',
                    endpoint: currentUrlString,
                    source: input.source,
                    testable: false,
                    detail: {
                        stage: 'url construction',
                        reason: error.message
                    },
                    description: `CORS Check could not verify ${currentUrlString} at the URL Construction stage: ${error.message}`
                }
            );
            return endpointResults;
        }

        const testScenarios = generateTestURL(currentUrlString);

        for (const newOriginURL of testScenarios) {
            try {
                const responseObject = await makeRequest(currentUrlString, input.method, { 'Origin': newOriginURL.originHeader });

                if (responseObject.headers?.['access-control-allow-origin'] === '*') {
                    endpointResults.push({
                        checkName: 'CORS Misconfiguration',
                        endpoint: currentUrlString,
                        source: input.source,
                        severity: 'High',
                        detail: {
                            method: input.method,
                            header: 'access-control-allow-origin',
                            status: 'Present',
                            value: '*',
                            originUsed: newOriginURL.originHeader,
                        },
                        description: 'The endpoint explicitly allows cross-origin access from any domain using the wildcard (*) origin header. This permits arbitrary external websites to read the HTTP response.',
                        remediation: 'Restrict the Access-Control-Allow-Origin header to a strict whitelist of trusted domains. Do not use wildcards unless the endpoint is specifically intended to be a fully public API.'
                    });
                    break;
                }
                else if (responseObject.headers?.['access-control-allow-origin'] === newOriginURL.originHeader && responseObject.headers?.['access-control-allow-credentials'] === 'true') {
                    endpointResults.push({
                        checkName: 'CORS Misconfiguration',
                        endpoint: currentUrlString,
                        source: input.source,
                        severity: 'Critical',
                        detail: {
                            method: input.method,
                            header: 'access-control-allow-origin',
                            status: 'Present',
                            value: newOriginURL.originHeader, 
                            originUsed: newOriginURL.originHeader,
                        },
                        description: "The endpoint blindly reflects the attacker-supplied Origin and allows credentials. This allows any malicious website to force a victim's browser to make authenticated requests and steal the sensitive response.",
                        remediation: 'Never combine dynamic Origin reflection with Access-Control-Allow-Credentials: true. Implement a strict, hardcoded server-side whitelist of trusted domains.'
                    });
                }
                else if (responseObject.headers?.['access-control-allow-origin'] === newOriginURL.originHeader) {
                    endpointResults.push({
                        checkName: 'CORS Misconfiguration',
                        endpoint: currentUrlString,
                        source: input.source,
                        severity: 'High',
                        detail: {
                            method: input.method,
                            header: 'access-control-allow-origin',
                            status: 'Present',
                            value: newOriginURL.originHeader,
                            originUsed: newOriginURL.originHeader,
                        },
                        description: 'The endpoint blindly reflects the attacker-supplied Origin header back into the response. While credentials are not permitted, any arbitrary website can still read unauthenticated responses from this endpoint.',
                        remediation: 'Stop dynamically echoing the user-supplied Origin header. Configure the server CORS policy to use a strict whitelist of approved domains.'
                    });
                }
                else if (!responseObject.headers?.['access-control-allow-origin'] && !responseObject.headers?.['access-control-allow-credentials']) {
                    // endpointResults.push({
                    //     checkName: 'CORS Misconfiguration',
                    //     endpoint: currentUrlString,
                    //     source: input.source,
                    //     severity: 'None',
                    //     detail: {
                    //         method: input.method,
                    //         headers: 'access-control-allow-origin, access-control-allow-credentials',
                    //         status: 'Absent',
                    //         value: 'None',
                    //         originUsed: newOriginURL.originHeader,
                    //     }
                    // });

                    // Do nothing since we decided to only push into results when there is some sort of severity, otherwise its just clutter which needs to be filtered later
                }
                else {
                    // endpointResults.push({
                    //     checkName: 'CORS Misconfiguration',
                    //     endpoint: currentUrlString,
                    //     source: input.source,
                    //     severity: 'None',
                    //     detail: {
                    //         method: input.method,
                    //         header: 'access-control-allow-origin',
                    //         status: responseObject.headers?.['access-control-allow-origin'] ? 'Present (Secure/Unmatched)' : 'Absent',
                    //         value: responseObject.headers?.['access-control-allow-origin'] || 'None',
                    //         originUsed: newOriginURL.originHeader,
                    //     }
                    // });

                    // Do nothing since we decided to only push into results when there is some sort of severity, otherwise its just clutter which needs to be filtered later
                }
            } catch (error) {
                endpointResults.push({
                    checkName: 'CORS Misconfiguration',
                    endpoint: currentUrlString,
                    source: input.source,
                    testable: false,
                    detail: {
                        method: input.method,
                        stage: 'response capturing',
                        originUsed: newOriginURL.originHeader,
                        reason: error.message
                    },
                    description: `CORS Misconfiguration Check could not verify ${currentUrlString} at the Response Capturing stage: ${error.message}`
                });
            }
        }
        
        return endpointResults;
    });

    const nestedResults = await Promise.all(endpointPromises);

    return nestedResults.flat(); 
}