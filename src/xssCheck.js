import { makeRequest } from "./requestHelper.js";

function parseResponse(url, responseObject, source, param, payload) {
	let reflectedInHeaders = false;

	for (const [headerName, headerValue] of Object.entries(responseObject.headers)) {
		const valueString = Array.isArray(headerValue) ? headerValue.join(' ') : headerValue;

		if (valueString && valueString.includes(payload)) {
			reflectedInHeaders = true;
			break;
		}
	}

	const reflectedInBody = typeof responseObject.body === 'string'
		? responseObject.body.includes(payload)
		: false;

	let severity;
	let description = '';
	let remediation = '';

	if (reflectedInBody) {
		severity = 'Critical';
		description = `The endpoint reflects untrusted user input via the '${param}' parameter (specifically, a payload containing dangerous HTML characters like <, >, ", and ') directly into the HTTP response body without proper escaping. This confirms a Reflected Cross-Site Scripting (XSS) vulnerability, which allows an attacker to execute arbitrary malicious JavaScript in a victim's browser.`;
		remediation = 'Implement strict, context-aware output encoding for all user-supplied data before rendering it in the response (e.g., convert < to &lt;). Utilize modern, security-focused templating engines that automatically escape variables, and never trust client-supplied input.';
	}
	else if (reflectedInHeaders) {
		severity = 'Medium';
		description = `The endpoint reflects untrusted user input via the '${param}' parameter directly into an HTTP response header without sanitization. While less directly exploitable for XSS than body reflection, this behavior can lead to HTTP Response Splitting, MIME-type sniffing bypasses, or cache poisoning.`;
		remediation = 'Avoid reflecting user input in HTTP response headers. If it is strictly necessary, strongly validate the input against a strict allowlist and strip any newline characters (\\r, \\n) to prevent header injection and HTTP response splitting attacks.';
	}

	return {
		checkName: 'XSS Check',
		endpoint: url,
		source: source,
		severity: severity,
		detail: {
			parameter: param,
			statusCode: responseObject.statusCode,
			reflectedInHeaders,
			reflectedInBody,
		},
		// Only attach description/remediation if a vulnerability was actually found
		...(severity && { description, remediation })
	};
}

async function runXssRequests(requestSpecs) {
	const allPromises = requestSpecs.map(async (spec) => {
		const { url, method, headers, source, param, payload, fallbackUrlString } = spec;

		if (!url) {
			return {
				checkName: 'XSS Check',
				endpoint: fallbackUrlString,
				source: source,
				testable: false,
				detail: {
					method: method,
					reason: spec.constructionError
				},
				description: `XSS Check could not verify ${fallbackUrlString} at the URL Construction stage: ${spec.constructionError}`
			};
		}

		try {
			const responseObject = await makeRequest(url, method, headers);

			return parseResponse(url, responseObject, source, param, payload);

		} catch (error) {
			return {
				checkName: 'XSS Check',
				endpoint: url,
				source: source,
				testable: false,
				detail: {
					stage: 'response capturing',
					method: method,
					reason: error.message
				},
				description: `XSS Check could not verify ${url} at the Response Capturing stage: ${error.message}`
			};
		}
	});

	const allSettledRequests = await Promise.allSettled(allPromises);

	return allSettledRequests.reduce((acc, request) => {
		if (request.status === 'fulfilled' && ((request.value.detail.reflectedInHeaders || request.value.detail.reflectedInBody) || Object.hasOwn(request.value, 'testable'))) {
			acc.push(request.value);
		}

		return acc;
	}, []);
}

export async function xssCookieCheck(url, pathMethod) {
    const payload = `XSSCANARY123<>"'`;

    // Categorized wordlist based on common API and web framework defaults
    const cookieWordlist = {
        frameworks: ['PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', 'connect.sid', '_session_id', '.AspNetCore.Session'],
        auth: ['session', 'sessionid', 'sid', 'auth', 'token', 'id_token', 'access_token', 'jwt'],
        state: ['csrf_token', 'xsrf_token', 'state', 'lang', 'theme', 'timezone'],
        tracking: ['analytics', 'track', 'visitor', 'guest', 'uid', 'device_id']
    };

    const flatWordlist = Object.values(cookieWordlist).flat();

    const requestSpecs = [];

    for (const { path, method, source } of pathMethod) {
        for (const cookieName of flatWordlist) {

            const fallbackUrlString = `${url}/${path}`;

            try {
                const urlObject = new URL(url);
                urlObject.pathname = path;

                requestSpecs.push({
                    url: urlObject.href,
                    method,
                    // Construct the Cookie header correctly: "Name=Value"
                    headers: { 'Cookie': `${cookieName}=${payload}` },
                    source,
                    param: cookieName, // Using the cookie name as 'param' maps perfectly to your parseResponse descriptions
                    payload,
                    fallbackUrlString
                });
            } catch (error) {
                requestSpecs.push({
                    url: null,
                    method,
                    source,
                    param: cookieName,
                    payload,
                    fallbackUrlString,
                    constructionError: error.message
                });
            }
        }
    }

    return runXssRequests(requestSpecs);
}

export async function xssQueryCheck(url, pathMethod) {
	const payload = `XSSCANARY123<>"'`;

	const wordlist = {
		identification: ['id', 'user', 'uid', 'account', 'session'],
		actions: ['action', 'cmd', 'task', 'execute', 'do'],
		navigation: ['page', 'redirect', 'url', 'next', 'back'],
		searchFilter: ['q', 'query', 'search', 'sort', 'filter'],
		tracking: ['utm_source', 'utm_medium', 'ref', 'referrer'],
		userContent: ['name', 'input', 'text', 'comment', 'message']
	};

	const flatWordlist = Object.values(wordlist).flat();

	const requestSpecs = [];

	for (const { path, method, source } of pathMethod) {
		for (const newParam of flatWordlist) {

			const fallbackUrlString = `${url}/${path}`;

			try {
				const urlObject = new URL(url);
				urlObject.pathname = path;
				urlObject.searchParams.append(newParam, payload);

				requestSpecs.push({
					url: urlObject.href,
					method,
					headers: undefined,
					source,
					param: newParam,
					payload,
					fallbackUrlString
				});
			} catch (error) {
				requestSpecs.push({
					url: null,
					method,
					source,
					param: newParam,
					payload,
					fallbackUrlString,
					constructionError: error.message
				});
			}
		}
	}

	return runXssRequests(requestSpecs);
}

export async function xssHeaderCheck(url, pathMethod) {
	const payload = `XSSCANARY123<>"'`;

	const headerWordlist = {
		clientInfo: ['User-Agent', 'Referer', 'Origin'],
		proxyChain: ['X-Forwarded-For', 'X-Forwarded-Host', 'X-Real-IP', 'X-Client-IP'],
		customApp: ['X-Requested-With', 'X-Api-Version', 'X-Debug'],
	};

	const flatWordlist = Object.values(headerWordlist).flat();

	const requestSpecs = [];

	for (const { path, method, source } of pathMethod) {
		for (const headerName of flatWordlist) {

			const fallbackUrlString = `${url}/${path}`;

			try {
				const urlObject = new URL(url);
				urlObject.pathname = path;

				requestSpecs.push({
					url: urlObject.href,
					method,
					headers: { [headerName]: payload },
					source,
					param: headerName,
					payload,
					fallbackUrlString
				});
			} catch (error) {
				requestSpecs.push({
					url: null,
					method,
					source,
					param: headerName,
					payload,
					fallbackUrlString,
					constructionError: error.message
				});
			}
		}
	}

	return runXssRequests(requestSpecs);
}