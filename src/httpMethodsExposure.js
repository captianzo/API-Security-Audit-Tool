import { makeRequest } from "./requestHelper.js";

async function makeOptionsRequest(url) {
    const findings = [];
    const responseObject = await makeRequest(url, 'OPTIONS');

    const allowHeader = responseObject.headers?.allow?.toUpperCase() || '';

    if (allowHeader) {
        if (allowHeader.includes('TRACE')) {
            findings.push({
                endpoint: url,
                header: 'allow',
                status: 'Present',
                value: 'TRACE',
                severity: 'Medium'
            });
        }
        if (allowHeader.includes('PUT')) {
            findings.push({
                endpoint: url,
                header: 'allow',
                status: 'Present',
                value: 'PUT',
                severity: 'Low'
            });
        }
        if (allowHeader.includes('DELETE')) {
            findings.push({
                endpoint: url,
                header: 'allow',
                status: 'Present',
                value: 'DELETE',
                severity: 'Low'
            });
        }
    }

    return findings;
}

async function makeTraceRequest(url) {
    const responseObject = await makeRequest(url, 'TRACE');

    if (responseObject.statusCode === 200) {
        return {
            endpoint: url,
            header: 'TRACE',
            status: 'Present',
            severity: 'Medium'
        };
    }
    return null; 
}

export async function checkMethodExposure(url, pathMethod) {
    const result = [];

    await Promise.all(pathMethod.map(async (input) => {
        let currentUrlString = `${url}/${input.path}`

        try {
            const newUrl = new URL(input.path, url);
            currentUrlString = newUrl.href;

            const optionsFindings = await makeOptionsRequest(newUrl.href);
            result.push(...optionsFindings);

            const traceFinding = await makeTraceRequest(newUrl.href);
            if (traceFinding) {
                result.push(traceFinding);
            }
        } catch (error) {
            result.push({
                endpoint: currentUrlString,
                method: ['OPTIONS', 'TRACE'],
                status: 'Untestable',
                reason: error.message
            })
        }
    }))

    return result;
}