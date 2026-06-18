import { makeRequest } from "./requestHelper.js";

async function makeOptionsRequest(url) {
    const findings = [];
    const responseObject = await makeRequest(url, 'OPTIONS');

    const allowHeader = responseObject.headers?.allow?.toUpperCase() || '';

    if (allowHeader) {
        if (allowHeader.includes('TRACE')) {
            findings.push({
                endpoint: url.href,
                header: 'allow',
                status: 'Present',
                value: 'TRACE',
                severity: 'Medium'
            });
        }
        if (allowHeader.includes('PUT')) {
            findings.push({
                endpoint: url.href,
                header: 'allow',
                status: 'Present',
                value: 'PUT',
                severity: 'Low'
            });
        }
        if (allowHeader.includes('DELETE')) {
            findings.push({
                endpoint: url.href,
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
            endpoint: url.href,
            header: 'TRACE',
            status: 'Present',
            severity: 'Medium'
        };
    }
    return null; 
}

export async function checkMethodExposure(inputUrl) {
    const result = [];
    const url = new URL(inputUrl);

    result.push(makeOptionsRequest(url));
    result.push(makeTraceRequest(url));

    const combinedArrayResult = await Promise.allSettled(result);

    return combinedArrayResult.reduce((acc, request) => {
        if (request.status === 'fulfilled') {
            const val = request.value;

            if (val) { 
                if (Array.isArray(val)) {
                    acc.push(...val);
                } else {
                    acc.push(val);
                }
            }
        }
        return acc;
    }, []);
}