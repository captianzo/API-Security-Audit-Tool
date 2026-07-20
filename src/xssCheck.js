import { makeRequest } from "./requestHelper.js";

export async function makeMultipleRequestsUsingQuerys(url, pathMethod) {
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

	const allPromises = [];

	for (const { path, method, source } of pathMethod) {

		const pathRequests = flatWordlist.map(async (newParam) => {

			let reflectedInHeaders = false;
			let fallbackUrlString = `${url}/${path}`;
			let urlObject;
			try {
				urlObject = new URL(url);
			} catch (error) {
				return {
					checkName: 'XSS Check',
					endpoint: fallbackUrlString,
					source: source,
					testable: false,
					detail: {
						method: method,
						reason: error.message
					},
					description: `XSS Check could not verify ${fallbackUrlString} at the URL Construction stage: ${error.message}`
				}
			}

			urlObject.pathname = path;
			urlObject.searchParams.append(newParam, payload);

			try {
				const responseObject = await makeRequest(urlObject.href, method);

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
					description = `The endpoint reflects untrusted user input via the '${newParam}' parameter (specifically, a payload containing dangerous HTML characters like <, >, ", and ') directly into the HTTP response body without proper escaping. This confirms a Reflected Cross-Site Scripting (XSS) vulnerability, which allows an attacker to execute arbitrary malicious JavaScript in a victim's browser.`;
					remediation = 'Implement strict, context-aware output encoding for all user-supplied data before rendering it in the response (e.g., convert < to &lt;). Utilize modern, security-focused templating engines that automatically escape variables, and never trust client-supplied input.';
				}
				else if (reflectedInHeaders) {
					severity = 'Medium';
					description = `The endpoint reflects untrusted user input via the '${newParam}' parameter directly into an HTTP response header without sanitization. While less directly exploitable for XSS than body reflection, this behavior can lead to HTTP Response Splitting, MIME-type sniffing bypasses, or cache poisoning.`;
					remediation = 'Avoid reflecting user input in HTTP response headers. If it is strictly necessary, strongly validate the input against a strict allowlist and strip any newline characters (\\r, \\n) to prevent header injection and HTTP response splitting attacks.';
				}

				return {
					checkName: 'XSS Check',
					endpoint: urlObject.href,
					source: source,
					severity: severity,
					detail: {
						parameter: newParam,
						statusCode: responseObject.statusCode,
						reflectedInHeaders,
						reflectedInBody,
					},
					// Only attach description/remediation if a vulnerability was actually found
					...(severity && { description, remediation })
				};
			} catch (error) {
				return {
					checkName: 'XSS Check',
					endpoint: urlObject.href,
					source: source,
					testable: false,
					detail: {
						stage: 'response capturing',
						method: method,
						reason: error.message
					},
					description: `XSS Check could not verify ${urlObject.href} at the Response Capturing stage: ${error.message}`
				};
			}
		});

		allPromises.push(...pathRequests);
	}

	const allSettledRequests = await Promise.allSettled(allPromises);

	return allSettledRequests.reduce((acc, request) => {
		if (request.status === 'fulfilled' && ((request.value.detail.reflectedInHeaders || request.value.detail.reflectedInBody) || Object.hasOwn(request.value, 'testable'))) {
			acc.push(request.value);
		}

		return acc;
	}, []);
}