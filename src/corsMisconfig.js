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
        const newUrl = new URL(input.path, url);
        const testScenarios = generateTestURL(newUrl.href);

        for (const newOriginURL of testScenarios) {
            try {
                const responseObject = await makeRequest(newUrl.href, 'GET', { 'Origin': newOriginURL.originHeader });

                if (responseObject.headers?.['access-control-allow-origin'] === '*') {
                    endpointResults.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        header: 'access-control-allow-origin',
                        status: 'Present',
                        value: '*',
                        originUsed: newOriginURL.originHeader,
                        severity: 'High'
                    });
                    break;
                }
                else if (responseObject.headers?.['access-control-allow-origin'] === newOriginURL.originHeader && responseObject.headers?.['access-control-allow-credentials'] === 'true') {
                    endpointResults.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        header: 'access-control-allow-origin',
                        status: 'Present',
                        value: newOriginURL.originHeader, 
                        originUsed: newOriginURL.originHeader,
                        severity: 'Critical'
                    });
                }
                else if (responseObject.headers?.['access-control-allow-origin'] === newOriginURL.originHeader) {
                    endpointResults.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        header: 'access-control-allow-origin',
                        status: 'Present',
                        value: newOriginURL.originHeader,
                        originUsed: newOriginURL.originHeader,
                        severity: 'High'
                    });
                }
                else if (!responseObject.headers?.['access-control-allow-origin'] && !responseObject.headers?.['access-control-allow-credentials']) {
                    endpointResults.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        headers: 'access-control-allow-origin, access-control-allow-credentials',
                        status: 'Absent',
                        value: 'None',
                        originUsed: newOriginURL.originHeader,
                        severity: 'None'
                    });
                }
                else {
                    endpointResults.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        header: 'access-control-allow-origin',
                        status: responseObject.headers?.['access-control-allow-origin'] ? 'Present (Secure/Unmatched)' : 'Absent',
                        value: responseObject.headers?.['access-control-allow-origin'] || 'None',
                        originUsed: newOriginURL.originHeader,
                        severity: 'None'
                    });
                }
            } catch (error) {
                endpointResults.push({
                    endpoint: newUrl.href,
                    method: input.method,
                    status: 'Untestable',
                    originUsed: newOriginURL.originHeader,
                    reason: error.message
                });
            }
        }
        
        return endpointResults;
    });

    const nestedResults = await Promise.all(endpointPromises);

    return nestedResults.flat(); 
}