import { makeRequest } from "./requestHelper.js";

async function makeOptionsRequest(url, source) {
    const findings = [];
    const responseObject = await makeRequest(url, 'OPTIONS');

    const allowHeader = responseObject.headers?.allow?.toUpperCase() || '';

    if (allowHeader) {
        if (allowHeader.includes('TRACE')) {
            findings.push({
                checkName: 'HTTP Methods Exposure',
                endpoint: url,
                source: source,
                severity: 'Medium',
                detail: {
                    header: 'allow',
                    status: 'Present',
                    value: 'TRACE',
                }
            });
        }
        if (allowHeader.includes('PUT')) {
            findings.push({
                checkName: 'HTTP Methods Exposure',
                endpoint: url,
                source: source,
                severity: 'Low',
                detail: {
                    header: 'allow',
                    status: 'Present',
                    value: 'PUT',
                }
            });
        }
        if (allowHeader.includes('DELETE')) {
            findings.push({
                checkName: 'HTTP Methods Exposure',
                endpoint: url,
                source: source,
                severity: 'Low',
                detail: {
                    header: 'allow',
                    status: 'Present',
                    value: 'DELETE',
                }
            });
        }
    }

    return findings;
}

async function makeTraceRequest(url, source) {
    const responseObject = await makeRequest(url, 'TRACE');

    if (responseObject.statusCode === 200) {
        return {
            checkName: 'HTTP Methods Exposure',
            endpoint: url,
            source: source,
            severity: 'Medium',
            detail: {
                header: 'TRACE',
                status: 'Present',
            }
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
        } catch (error) {
            result.push({
                checkName: 'HTTP Methods Exposure',
                endpoint: currentUrlString,
                source: input.source,
                testable: false,
                detail: {
                    stage: 'url construction',
                    reason: error.message
                }
            })
            return;
        }

        try {
            const optionsFindings = await makeOptionsRequest(currentUrlString, input.source);
            result.push(...optionsFindings);

        } catch (error) {
            result.push({
                checkName: 'HTTP Methods Exposure',
                endpoint: currentUrlString,
                source: input.source,
                testable: false,
                detail: {
                    method: 'OPTIONS',
                    reason: error.message
                }
            })
        }
        
        try {
            const traceFinding = await makeTraceRequest(currentUrlString, input.source);
            if (traceFinding) {
                result.push(traceFinding);
            }
        } catch (error) {
            result.push({
                checkName: 'HTTP Methods Exposure',
                endpoint: currentUrlString,
                source: input.source,
                testable: false,
                detail: {
                    method: 'TRACE',
                    reason: error.message
                }
            })
        }
    }))

    return result;
}