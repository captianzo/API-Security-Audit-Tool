import { makeRequest } from "./requestHelper.js";

// 1. The Centralized Content Library
const riskProfiles = {
    database_exposure: {
        description: "The application exposed raw database error messages in the HTTP response. This reveals structural details about the underlying schema, query logic, or database engine type.",
        remediation: "Implement global try-catch blocks or custom database abstraction layers that catch raw database exceptions. Return generic user-friendly error messages to the client while logging the detailed exception securely to an internal log management system."
    },
    application_stacktrace: {
        description: "A runtime execution stack trace was detected in the response body. This leaks application logic, internal function names, source file structures, and occasionally software library versions.",
        remediation: "Disable verbose error debugging utilities in production configurations (e.g., set 'NODE_ENV=production' for Express, turn off 'DEBUG' in Django, or configure a global Spring '@ControllerAdvice' error handler). Ensure the application falls back to a generic fallback error template."
    },
    filesystem_leak: {
        description: "The application exposed absolute local server filesystem paths in the server response. This discloses the underlying server OS structure and environment conventions.",
        remediation: "Sanitize application error handlers and system messages to scrub absolute paths before responses are transmitted. Use relative routing or generic error messages rather than letting system-level exceptions bubbles up directly to the user."
    },
    server_fingerprint: {
        description: "The response explicitly identified the specific web server framework version or runtime layout during an error state.",
        remediation: "Configure the web server or application framework to hide version banners (e.g., set ServerTokens ProductOnly in Apache, or remove detailed error templates in Apache Tomcat's web.xml configuration)."
    }
};

export async function checkVerboseErrors(url, pathMethod) {
    const result = [];

    // 2. Indicators explicitly tagged with their architectural profile key
    const errorIndicators = [
        { pattern: 'SQL syntax', baseSeverity: 'Critical', profile: 'database_exposure' },
        { pattern: 'ORA-', baseSeverity: 'Critical', profile: 'database_exposure' },
        { pattern: 'pg_', baseSeverity: 'Critical', profile: 'database_exposure' },
        { pattern: 'mysql_fetch_array()', baseSeverity: 'Critical', profile: 'database_exposure' },

        { pattern: 'Traceback (most recent call last):', baseSeverity: 'High', profile: 'application_stacktrace' },
        { pattern: 'Exception Value:', baseSeverity: 'High', profile: 'application_stacktrace' },
        { pattern: 'werkzeug.exceptions', baseSeverity: 'High', profile: 'application_stacktrace' },

        { pattern: 'Whitelabel Error Page', baseSeverity: 'Low', profile: 'server_fingerprint' },
        { pattern: 'java.lang.NullPointerException', baseSeverity: 'High', profile: 'application_stacktrace' },
        { pattern: 'org.springframework.', baseSeverity: 'Medium', profile: 'application_stacktrace' },
        { pattern: 'Apache Tomcat/', baseSeverity: 'Low', profile: 'server_fingerprint' },

        { pattern: 'Action Controller: Exception caught', baseSeverity: 'High', profile: 'application_stacktrace' },
        { pattern: 'Routing Error', baseSeverity: 'Low', profile: 'server_fingerprint' },

        { pattern: '<pre>Error:', baseSeverity: 'Medium', profile: 'application_stacktrace' },
        { pattern: '&nbsp;at&nbsp;', baseSeverity: 'Medium', profile: 'application_stacktrace' },
        { pattern: 'at Object.', baseSeverity: 'Medium', profile: 'application_stacktrace' },
        { pattern: 'at Function.', baseSeverity: 'Medium', profile: 'application_stacktrace' },

        { pattern: 'Fatal error:', baseSeverity: 'High', profile: 'application_stacktrace' },
        { pattern: 'Stack trace:', baseSeverity: 'Medium', profile: 'application_stacktrace' },

        { pattern: '/var/www/html/', baseSeverity: 'Medium', profile: 'filesystem_leak' },
        { pattern: 'C:\\inetpub\\wwwroot\\', baseSeverity: 'Medium', profile: 'filesystem_leak' }
    ];

    const errorRegexIndicators = [
        { pattern: /at .*:\d+:\d+/, baseSeverity: 'Medium', profile: 'application_stacktrace' }
    ];

    await Promise.all(pathMethod.map(async (input) => {
        let currentUrlString = `${url}/${input.path}`;

        try {
            const newUrl = new URL(input.path, url);
            currentUrlString = newUrl.href;
        } catch (error) {
            result.push({
                checkName: 'Verbose Error',
                endpoint: currentUrlString,
                source: input.source,
                testable: false,
                detail: { stage: 'url construction', reason: error.message },
                description: `Verbose Error Check could not verify ${currentUrlString} at the URL Construction stage: ${error.message}`
            });
            return;
        }

        try {
            const responseObject = await makeRequest(currentUrlString, 'GET');
            const statusCode = responseObject.statusCode;

            // Helper to build consistent report payload from profile matching
            const createReportEntry = (indicator, matchedPatternText) => {
                const finalSeverity = statusCode >= 500
                    ? (indicator.baseSeverity === 'Medium' ? 'High' : indicator.baseSeverity)
                    : indicator.baseSeverity;
                    
                const profile = riskProfiles[indicator.profile];

                const detail = {
                    statusCode: statusCode,
                    matchedPattern: matchedPatternText,
                    profileKey: indicator.profile
                };

                if (statusCode === 404) {
                    detail.respondedWith404 = true;
                }

                return {
                    checkName: 'Verbose Error',
                    endpoint: currentUrlString,
                    source: input.source,
                    severity: finalSeverity,
                    detail: detail,
                    description: profile.description,
                    remediation: profile.remediation
                };
            };

            for (const errMsg of errorIndicators) {
                if (responseObject.body.includes(errMsg.pattern)) {
                    result.push(createReportEntry(errMsg, errMsg.pattern));
                }
            }

            for (const regexIndicator of errorRegexIndicators) {
                if (regexIndicator.pattern.test(responseObject.body)) {
                    result.push(createReportEntry(regexIndicator, regexIndicator.pattern.toString()));
                }
            }
        } catch (error) {
            result.push({
                checkName: 'Verbose Error',
                endpoint: currentUrlString,
                source: input.source,
                testable: false,
                detail: { method: input.method, reason: error.message },
                description: `Verbose Error Check could not verify ${currentUrlString} at the Response Capturing stage: ${error.message}`
            });
        }
    }));

    return result;
}