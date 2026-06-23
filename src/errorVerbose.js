import { makeRequest } from "./requestHelper.js";

function calculateSeverity(baseSeverity, statusCode) {
    if (statusCode >= 500) {
        // 500s are actual crashes. Keep base or elevate.
        return baseSeverity === 'Medium' ? 'High' : baseSeverity;
    }
    if (statusCode === 404) {
        // 404s are usually framework routing debug pages. Downgrade to minimize noise.
        return 'Low'; 
    }
    // For 400s or weird 200s, trust the base severity of the pattern
    return baseSeverity;
}

export async function checkVerboseErrors(url, pathMethod) {
    const result = [];

    const errorIndicators = [
        // --- DATABASES (Highest Priority) ---
        { pattern: 'SQL syntax', baseSeverity: 'Critical' },
        { pattern: 'ORA-', baseSeverity: 'Critical' },
        { pattern: 'pg_', baseSeverity: 'Critical' },
        { pattern: 'mysql_fetch_array()', baseSeverity: 'Critical' },

        // --- PYTHON (Django / Flask) ---
        { pattern: 'Traceback (most recent call last):', baseSeverity: 'High' },
        { pattern: 'Exception Value:', baseSeverity: 'High' },
        { pattern: 'werkzeug.exceptions', baseSeverity: 'High' },

        // --- JAVA (Spring Boot / Tomcat) ---
        { pattern: 'Whitelabel Error Page', baseSeverity: 'High' },
        { pattern: 'java.lang.NullPointerException', baseSeverity: 'High' },
        { pattern: 'org.springframework.', baseSeverity: 'Medium' },
        { pattern: 'Apache Tomcat/', baseSeverity: 'Low' },

        // --- RUBY (Rails) ---
        { pattern: 'Action Controller: Exception caught', baseSeverity: 'High' },
        { pattern: 'Routing Error', baseSeverity: 'Medium' },

        // --- NODE.JS (Express) ---
        { pattern: '<pre>Error:', baseSeverity: 'Medium' },
        { pattern: '&nbsp;at&nbsp;', baseSeverity: 'Medium' }, // HTML encoded stack traces
        { pattern: 'at Object.', baseSeverity: 'Medium' },
        { pattern: 'at Function.', baseSeverity: 'Medium' },

        // --- PHP ---
        { pattern: 'Fatal error:', baseSeverity: 'High' },
        { pattern: 'Stack trace:', baseSeverity: 'Medium' },

        // --- INTERNAL PATHS ---
        { pattern: '/var/www/html/', baseSeverity: 'Medium' },
        { pattern: 'C:\\inetpub\\wwwroot\\', baseSeverity: 'Medium' }
    ];

    const errorRegexIndicators = [
        {
            pattern: /at .*:\d+:\d+/,
            baseSeverity: 'Medium'
        }
    ];

    await Promise.all(pathMethod.map(async (input) => {
        const newUrl = new URL(input.path, url);

        try {
            const responseObject = await makeRequest(newUrl.href, 'GET');
            const statusCode = responseObject.statusCode;

            for (const errMsg of errorIndicators) {
                if (responseObject.body.includes(errMsg.pattern)) {
                    
                    const finalSeverity = calculateSeverity(errMsg.baseSeverity, statusCode);

                    result.push({
                        endpoint: newUrl.href,
                        statusCode: statusCode, // Added status code to the report
                        pattern: errMsg.pattern,
                        severity: finalSeverity // Using the dynamically calculated severity
                    });
                }
            }

            for (const regexIndicator of errorRegexIndicators) {
                if (regexIndicator.pattern.test(responseObject.body)) {
                    
                    const finalSeverity = calculateSeverity(regexIndicator.baseSeverity, statusCode);

                    result.push({
                        endpoint: newUrl.href,
                        statusCode: statusCode,
                        pattern: regexIndicator.pattern.toString(),
                        severity: finalSeverity
                    });
                }
            }
        } catch (error) {
            result.push({
                endpoint: newUrl.href,
                method: input.method,
                status: 'Untestable',
                reason: error.message
            });
        }
    }));

    return result;
}