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

	const possibleMethodSeverities = {
		GET: 'Medium/High',
		POST: 'High',
		PUT: 'High',
		DELETE: 'High'
	};

	const result = pathMethod.map(async (input) => {
		const newUrl = new URL(input.path, url);

		let responseObject;

		try {
			responseObject = await makeRequest(newUrl.href, input.method);
		} catch (error) {
			return {
			endpoint: newUrl.href,
			method: input.method,
			status: 'Untestable',
			reason: error.message
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

			return {
				endpoint: newUrl.href,
				method: input.method,
				statusCode: responseObject.statusCode,
				status: 'Vulnerable (Missing Auth)',
				severity: possibleMethodSeverities[input.method],
				confidence,
				findings: dynamicFindings
			};
		}

		return {
			endpoint: newUrl.href,
			method: input.method,
			statusCode: responseObject.statusCode,
			status: 'Untestable',
			reason: 'Status Code outside testable range (200-204)'
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