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
                severity: 'Medium', // Advertised, but dangerous by nature
                detail: {
                    header: 'allow',
                    status: 'Present',
                    value: 'TRACE',
                },
                description: 'The endpoint\'s OPTIONS response explicitly lists the TRACE method in its Allow header. While this doesn\'t confirm exploitability, TRACE is a diagnostic method that can be abused for Cross-Site Tracing (XST) attacks.',
                remediation: 'Disable the TRACE method globally in the web server configuration (e.g., \'TraceEnable off\' in Apache) to prevent potential XST attacks, which will automatically remove it from the Allow header.'
            });
        }
        
        // Helper to push PUT and DELETE
        const checkStateChangingMethod = (methodName) => {
            if (allowHeader.includes(methodName)) {
                findings.push({
                    checkName: 'HTTP Methods Exposure',
                    endpoint: url,
                    source: source,
                    severity: 'Low', // Kept Low because it's just an advertisement, not a confirmed bypass
                    detail: {
                        header: 'allow',
                        status: 'Present',
                        value: methodName,
                    },
                    description: `The endpoint advertises support for the ${methodName} method in its Allow header. While this does not guarantee the method is unauthenticated or exploitable, it provides attackers with reconnaissance data about state-changing API capabilities.`,
                    remediation: `Verify that ${methodName} requests to this endpoint are strictly authenticated and authorized. If the application does not actually utilize this method here, configure the routing framework to reject it and remove it from the Allow header.`
                });
            }
        };

        checkStateChangingMethod('PUT');
        checkStateChangingMethod('POST');
        checkStateChangingMethod('DELETE');
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
            severity: 'High', // Upgraded to High because the vulnerability is successfully confirmed
            detail: {
                header: 'TRACE',
                status: 'Present',
            },
            description: 'The server successfully executed a TRACE request and returned a 200 OK status. This confirms the endpoint actively reflects requests, exposing the application to Cross-Site Tracing (XST) attacks which can be used to bypass HttpOnly flags and steal session cookies.',
            remediation: 'Immediately disable the TRACE method on the web server (e.g., set \'TraceEnable off\' in Apache, or configure the application proxy/framework to outright reject TRACE requests). Diagnostic HTTP methods should never be enabled in production.'
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
                },
                description: `HTTP Methods Exposure Check could not verify ${currentUrlString} at the URL Construction stage: ${error.message}`
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
                },
                description: `HTTP Methods Exposure Check could not verify ${currentUrlString} at the Response Capturing for OPTIONS Request stage: ${error.message}`
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
                },
                description: `HTTP Methods Exposure Check could not verify ${currentUrlString} at the Response Capturing for TRACE Request stage: ${error.message}`
            })
        }
    }))

    return result;
}