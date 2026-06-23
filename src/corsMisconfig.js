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
    const result = [];

    await Promise.all(pathMethod.map(async (input) => {
        const newUrl = new URL(input.path, url);
        const testScenarios = generateTestURL(newUrl.href);

        for (const newURL of testScenarios) {
            try {
                const responseObject = await makeRequest(newUrl.href, 'GET', { 'Origin': newURL.originHeader });

                if (responseObject.headers?.['access-control-allow-origin'] === '*') {
                    result.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        header: 'access-control-allow-origin',
                        status: 'Present',
                        value: '*',
                        originUsed: newURL.originHeader,
                        severity: 'High'
                    });
                }
                else if (responseObject.headers?.['access-control-allow-origin'] === newURL.originHeader && responseObject.headers?.['access-control-allow-credentials'] === 'true') {
                    result.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        header: 'access-control-allow-origin',
                        status: 'Present',
                        value: newURL.originHeader, 
                        originUsed: newURL.originHeader,
                        severity: 'Critical'
                    });
                }
                else if (responseObject.headers?.['access-control-allow-origin'] === newURL.originHeader) {
                    result.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        header: 'access-control-allow-origin',
                        status: 'Present',
                        value: newURL.originHeader,
                        originUsed: newURL.originHeader,
                        severity: 'High'
                    });
                }
                else if (!responseObject.headers?.['access-control-allow-origin'] && !responseObject.headers?.['access-control-allow-credentials']) {
                    result.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        headers: 'access-control-allow-origin, access-control-allow-credentials',
                        status: 'Absent',
                        value: 'None',
                        originUsed: newURL.originHeader,
                        severity: 'None'
                    });
                }
                else {
                    result.push({
                        endpoint: newUrl.href,
                        method: input.method,
                        header: 'access-control-allow-origin',
                        status: responseObject.headers?.['access-control-allow-origin'] ? 'Present (Secure/Unmatched)' : 'Absent',
                        value: responseObject.headers?.['access-control-allow-origin'] || 'None',
                        originUsed: newURL.originHeader,
                        severity: 'None'
                    });
                }
            } catch (error) {
                result.push({
                    endpoint: newUrl.href,
                    method: input.method,
                    status: 'Untestable',
                    originUsed: newURL.originHeader,
                    reason: error.message
                });
            }
        }
    }));

    return result; 
}