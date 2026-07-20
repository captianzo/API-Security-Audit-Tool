import { makeRequest } from "./requestHelper.js";

function checkRoute(path) {
	const sensitivePathKeywords = [
		'admin', 'auth', 'login', 'register', 'account', 'user', 'users',
		'profile', 'internal', 'manage', 'management', 'settings', 'config',
		'dashboard', 'billing', 'payment', 'payments', 'delete', 'remove',
		'private', 'secure', 'session', 'token', 'credential', 'password',
		'reset', 'backup', 'debug', 'staff', 'employee', 'hr', 'finance', 'secret'
	];

	const result = {
		path: path,
		matchedKeywords: []
	};

	let decodedPath;

	try {
		decodedPath = decodeURIComponent(path).toLowerCase();
	} catch (error) {
		decodedPath = path.toLowerCase();
	}

	for (const keyword of sensitivePathKeywords) {
		if (decodedPath.includes(keyword)) {
			result.matchedKeywords.push(keyword);
		}
	}

	return result;
}

function collectKeys(value, collectedKeys = []) {
	if (value === null || value === undefined) {
		return collectedKeys;
	}

	if (Array.isArray(value)) {
		for (const element of value) {
			collectKeys(element, collectedKeys);
		}
	}
	else if (typeof value === 'object') {
		const keys = Object.keys(value);
		for (const key of keys) {
			collectedKeys.push(key);
			collectKeys(value[key], collectedKeys);
		}
	}

	return collectedKeys;
}

function checkBody(body) {
	const sensitiveBodyKeywords = [
		'email', 'password', 'passwd', 'pwd', 'token', 'accesstoken',
		'refreshtoken', 'apikey', 'secret', 'ssn', 'creditcard', 'cardnumber',
		'cvv', 'balance', 'salary', 'income', 'phone', 'address', 'dob',
		'sessionid', 'authtoken', 'role', 'isadmin', 'permissions',
		'privatekey', 'bankaccount', 'routingnumber', 'taxid', 'passport'
	];

	let result = {
		matchedKeywords: [],
	}

	let parsedBody;

	try {
		parsedBody = JSON.parse(body);
		result.matchSource = 'structured';
		const extractedKeys = collectKeys(parsedBody);

		for (const keyword of sensitiveBodyKeywords) {
			const isMatch = extractedKeys.some(key => {
				return key.toLowerCase().includes(keyword.toLowerCase());
			})

			if (isMatch) {
				result.matchedKeywords.push(keyword);
			}
		}

	} catch (error) {
		result.matchSource = 'unstructured';
		parsedBody = body.toLowerCase();
		for (const keyword of sensitiveBodyKeywords) {
			if (parsedBody.includes(keyword)) {
				result.matchedKeywords.push(keyword);
			}
		}
	}

	return result;
}

export async function checkMissingAuth(url, pathMethod) {

	const methodSeverityMap = {
		POST: 'High',
		PUT: 'High',
		PATCH: 'High',
		DELETE: 'Critical',
		GET: 'Medium'
	};

	const decideGetSeverity = {
		Certain: 'High',
		Firm: 'Medium',
		Tentative: 'Low'
	}

	const result = pathMethod.map(async (input) => {
		let currentUrlString = `${url}/${input.path}`

		try {
			const newUrl = new URL(input.path, url);
			currentUrlString = newUrl.href;
		} catch (error) {
			return {
				checkName: 'Missing Authentication Detection',
				endpoint: currentUrlString,
				source: input.source,
				testable: false,
				detail: {
					method: input.method,
					reason: error.message
				},
				description: `Missing Authentication Detection Check could not verify ${currentUrlString} at the URL Construction stage: ${error.message}`
			}
		}

		if (input.method === 'HEAD') {
			return {
				checkName: 'Missing Authentication Detection',
				endpoint: currentUrlString,
				source: input.source,
				testable: false,
				detail: {
					method: input.method,
					reason: 'HEAD returns no body, cannot assess data sensitivity'
				},
				description: 'The HEAD method was excluded from authentication testing. HEAD requests do not return a response body, preventing the scanner from analyzing the response for sensitive data exposure.'
			};
		}

		if (input.method === 'OPTIONS') {
			return {
				checkName: 'Missing Authentication Detection',
				endpoint: currentUrlString,
				source: input.source,
				testable: false,
				detail: {
					method: input.method,
					reason: 'OPTIONS is expected to be publicly accessible'
				},
				description: 'The OPTIONS method was excluded from authentication testing. OPTIONS is primarily used for cross-origin preflight requests and is intentionally unauthenticated by design.'
			};
		}

		if (!methodSeverityMap[input.method]) {
			return {
				checkName: 'Missing Authentication Detection',
				endpoint: currentUrlString,
				source: input.source,
				testable: false,
				detail: {
					method: input.method,
					reason: 'method not recognized for auth-severity mapping'
				},
				description: `The HTTP method ${input.method} was excluded from testing because it falls outside the targeted scope for unauthenticated access risks.`
			};
		}

		let responseObject;

		try {
			responseObject = await makeRequest(currentUrlString, input.method);
		} catch (error) {
			return {
				checkName: 'Missing Authentication Detection',
				endpoint: currentUrlString,
				source: input.source,
				testable: false,
				detail: {
					method: input.method,
					reason: error.message
				},
				description: `Missing Authentication Detection Check could not verify ${currentUrlString} at the Request Execution stage: ${error.message}`
			};
		}

		if (responseObject.statusCode >= 200 && responseObject.statusCode <= 204) {
			const pathAnalysis = checkRoute(input.path);
			const bodyAnalysis = checkBody(responseObject.body || "");

			const pathMatches = pathAnalysis.matchedKeywords;
			const bodyMatches = bodyAnalysis.matchedKeywords;

			let confidence;
			if (pathMatches.length > 0 && bodyMatches.length > 0) {
				confidence = 'Certain';
			} else if (pathMatches.length > 0 || bodyMatches.length > 0) {
				confidence = 'Firm';
			} else {
				confidence = 'Tentative';
			}

			const dynamicFindings = {};
			if (pathMatches.length > 0) {
				dynamicFindings.pathExposedKeywords = pathMatches;
			}
			if (bodyMatches.length > 0) {
				dynamicFindings.bodyExposedKeywords = bodyMatches;
				dynamicFindings.bodyMatchSource = bodyAnalysis.matchSource;
			}

			// Build a dynamic description based on what triggered the alert
			let evidenceString = 'without requiring any authentication.';
			if (confidence === 'Certain' || confidence === 'Firm') {
				const triggers = [];
				if (pathMatches.length > 0) triggers.push(`sensitive keywords in the URL path (${pathMatches.join(', ')})`);
				if (bodyMatches.length > 0) triggers.push(`sensitive keywords in the response body (${bodyMatches.join(', ')})`);
				evidenceString = `without requiring authentication. The scanner identified this as a high-risk exposure due to the presence of ${triggers.join(' and ')}.`;
			}

			if (input.method === 'GET') {
				return {
					checkName: 'Missing Authentication Detection',
					endpoint: currentUrlString,
					source: input.source,
					severity: decideGetSeverity[confidence],
					detail: {
						method: input.method,
						statusCode: responseObject.statusCode,
						status: 'Vulnerable (Missing Auth)',
						confidence,
						findings: dynamicFindings
					},
					description: `The endpoint successfully processed a ${input.method} request ${evidenceString}`,
					remediation: `Implement robust authentication (e.g., JWT, OAuth, or secure session cookies) for this endpoint. Ensure that all requests attempting to access sensitive data or perform state-changing operations (${input.method}) are strictly validated for a valid and unexpired authentication token before processing.`
				};
			}
			else {
				return {
					checkName: 'Missing Authentication Detection',
					endpoint: currentUrlString,
					source: input.source,
					severity: methodSeverityMap[input.method],
					detail: {
						method: input.method,
						statusCode: responseObject.statusCode,
						status: 'Vulnerable (Missing Auth)',
						confidence,
						findings: dynamicFindings
					},
					description: `The endpoint successfully processed a ${input.method} request ${evidenceString}`,
					remediation: `Implement robust authentication (e.g., JWT, OAuth, or secure session cookies) for this endpoint. Ensure that all requests attempting to access sensitive data or perform state-changing operations (${input.method}) are strictly validated for a valid and unexpired authentication token before processing.`
				};
			}

		}

		return {
			checkName: 'Missing Authentication Detection',
			endpoint: currentUrlString,
			source: input.source,
			testable: false,
			detail: {
				method: input.method,
				statusCode: responseObject.statusCode,
				reason: 'Status Code outside testable range (200-204)'
			},
			description: `The endpoint returned a ${responseObject.statusCode} status code. The authentication check was aborted because a non-success status indicates the resource is either properly gated (e.g., 401/403) or unresolvable, preventing accurate verification.`
		};
	});

	const returnedResults = await Promise.allSettled(result);

	return returnedResults.reduce((acc, request) => {
		if (request.status === 'fulfilled') {
			acc.push(request.value);
		}
		if (request.status === 'rejected') {
			acc.push(request.reason);
		}
		return acc;
	}, []);
}