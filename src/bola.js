import { makeRequest } from "./requestHelper.js";
import { collectKeys } from "./jsonUtils.js";

const COMPARISON = { MATCH: 'match', MISMATCH: 'mismatch', UNKNOWN: 'unknown' };
const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const PLACEHOLDER_REGEX = /\{([^}]+)\}/g;

const JSON_MIN_MATCHED_KEYS = 2;
const JSON_MIN_MATCH_RATIO = 0.7;
const FALLBACK_LENGTH_TOLERANCE = 0.15;

const CONFIDENCE_SEVERITY = {
	Certain: 'Critical',
	Firm: 'High',
	Tentative: 'Medium'
};

const BOLA_REMEDIATION = 'Enforce object-level authorization on every request: verify server-side that the authenticated caller is actually permitted to access the specific object identified by the request, rather than only checking that the caller holds a valid token. Do not rely on an object ID being hard to guess.';

function validateEntry(endpoint) {
	const errors = [];

	if (typeof endpoint.endpoint_template !== 'string' || endpoint.endpoint_template.length === 0) {
		errors.push('endpoint_template must be a non-empty string');
	}
	if (typeof endpoint.http_method !== 'string' || endpoint.http_method.length === 0) {
		errors.push('http_method must be a non-empty string');
	}
	if (typeof endpoint.parameters !== 'object' || endpoint.parameters === null) {
		errors.push('parameters must be an object');
	}

	if (errors.length === 0) {
		const placeholders = [...endpoint.endpoint_template.matchAll(PLACEHOLDER_REGEX)].map(match => match[1]);
		const missingParams = placeholders.filter(key => !(key in endpoint.parameters));
		if (missingParams.length > 0) {
			errors.push(`endpoint_template references placeholder(s) [${missingParams.join(', ')}] not present in parameters`);
		}
	}

	return errors;
}

function buildUrl(url, template, parameters) {
	let resolvedPath = template;
	for (const [key, value] of Object.entries(parameters)) {
		resolvedPath = resolvedPath.split(`{${key}}`).join(encodeURIComponent(value));
	}

	return new URL(resolvedPath, url).toString();
}

function normalizeContentType(contentType) {
	if (!contentType) {
		return '';
	}
	return contentType.split(';')[0].trim().toLowerCase();
}

function tryParseJson(body) {
	try {
		return JSON.parse(body);
	} catch (error) {
		return undefined;
	}
}

function untestableResult(endpoint, detail, description) {
	return {
		checkName: 'BOLA Detection',
		endpoint,
		source: 'user-specified',
		testable: false,
		detail,
		description
	};
}

function vulnerableFinding(targetUrl, baseDetail, confidence, extraDetail, descriptionSuffix) {
	return {
		checkName: 'BOLA Detection',
		endpoint: targetUrl,
		source: 'user-specified',
		severity: CONFIDENCE_SEVERITY[confidence],
		detail: { ...baseDetail, vulnerable: true, confidence, ...extraDetail },
		description: `BOLA/IDOR vulnerability detected (${confidence} confidence) on ${targetUrl} [${baseDetail.test_id}]${descriptionSuffix}`,
		remediation: BOLA_REMEDIATION
	};
}

// Compares two responses ({ statusCode, headers, body }) -> { result, mode, detail }.
function compareResponses(responseA, responseB) {
	const parsedA = tryParseJson(responseA.body);
	const parsedB = tryParseJson(responseB.body);

	if (parsedA !== undefined && parsedB !== undefined) {
		const keysA = new Set(collectKeys(parsedA));
		const keysB = new Set(collectKeys(parsedB));
		const onlyInA = [...keysA].filter(key => !keysB.has(key));
		const onlyInB = [...keysB].filter(key => !keysA.has(key));
		const matchedKeyCount = keysA.size - onlyInA.length;

		if (keysA.size === 0) {
			return {
				result: COMPARISON.UNKNOWN,
				mode: 'json',
				detail: { matchedKeyCount: 0, onlyInA, onlyInB, reason: 'baseline has no comparable key structure (bare value, null, or empty object)' }
			};
		}

		const matchRatio = matchedKeyCount / keysA.size;
		const result = (matchedKeyCount >= JSON_MIN_MATCHED_KEYS && matchRatio >= JSON_MIN_MATCH_RATIO)
			? COMPARISON.MATCH
			: COMPARISON.MISMATCH;

		return {
			result,
			mode: 'json',
			detail: { matchedKeyCount, matchRatio, onlyInA, onlyInB }
		};
	}

	if (parsedA === undefined && parsedB === undefined) {
		const contentTypeA = normalizeContentType(responseA.headers['content-type']);
		const contentTypeB = normalizeContentType(responseB.headers['content-type']);
		const lengthA = responseA.body.length;
		const lengthB = responseB.body.length;

		if (lengthA === 0 && lengthB === 0) {
			return {
				result: COMPARISON.UNKNOWN,
				mode: 'fallback',
				detail: { contentTypeA, contentTypeB, lengthA, lengthB, reason: 'both bodies are empty, nothing to compare' }
			};
		}

		if (contentTypeA !== contentTypeB) {
			return {
				result: COMPARISON.MISMATCH,
				mode: 'fallback',
				detail: { contentTypeA, contentTypeB, lengthA, lengthB }
			};
		}

		const longer = Math.max(lengthA, lengthB);
		const diff = Math.abs(lengthA - lengthB);
		const diffRatio = diff / longer;

		return {
			result: diffRatio <= FALLBACK_LENGTH_TOLERANCE ? COMPARISON.MATCH : COMPARISON.MISMATCH,
			mode: 'fallback',
			detail: { contentTypeA, contentTypeB, lengthA, lengthB, diffRatio }
		};
	}

	return {
		result: COMPARISON.UNKNOWN,
		detail: { reason: 'One response is JSON and the other is not' }
	};
}

function baselineHint(statusCode) {
	if (statusCode === 401) return 'TOKEN_A was rejected (likely expired or invalid). Refresh TOKEN_A and re-run.';
	if (statusCode === 403) return 'TOKEN_A is not permitted to access this object, but this config entry assumes TOKEN_A owns it. Check the object ID or the token.';
	if (statusCode === 404) return 'the object was not found. Check the ID in parameters.';
	return `unexpected baseline status ${statusCode}.`;
}

export async function checkBola(url, bolaConfig, { tokenA, tokenB } = {}) {
	if (bolaConfig === undefined) {
		return [untestableResult(url, { reason: 'no --bola-config provided' }, 'BOLA check skipped: no --bola-config provided')];
	}

	const result = bolaConfig.map(async (endpoint, index) => {
		const baseDetail = { method: endpoint.http_method, test_id: endpoint.test_id ?? `entry_${index + 1}` };

		const validationErrors = validateEntry(endpoint);
		if (validationErrors.length > 0) {
			return untestableResult(
				url,
				{ ...baseDetail, reason: validationErrors.join('; ') },
				`BOLA Detection Check could not process config entry [${baseDetail.test_id}]: ${validationErrors.join('; ')}`
			);
		}

		let targetUrl;
		try {
			targetUrl = buildUrl(url, endpoint.endpoint_template, endpoint.parameters);
		} catch (error) {
			return untestableResult(
				url,
				{ ...baseDetail, reason: error.message },
				`BOLA Detection Check could not verify ${url} at the URL Construction stage [${baseDetail.test_id}]: ${error.message}`
			);
		}

		if (STATE_CHANGING_METHODS.has(endpoint.http_method) && !endpoint.confirm_state_changing) {
			return untestableResult(
				targetUrl,
				{ ...baseDetail, reason: 'state-changing method requires explicit opt-in' },
				`BOLA Detection Check skipped ${endpoint.http_method} ${targetUrl} [${baseDetail.test_id}]: state-changing methods can mutate the target object as a side effect of testing. Set "confirm_state_changing": true on this config entry to opt in.`
			);
		}

		const [settledA, settledB] = await Promise.allSettled([
			makeRequest(targetUrl, endpoint.http_method, { "Authorization": "Bearer " + tokenA }),
			makeRequest(targetUrl, endpoint.http_method, { "Authorization": "Bearer " + tokenB })
		]);

		if (settledA.status === 'rejected') {
			return untestableResult(
				targetUrl,
				{ ...baseDetail, reason: settledA.reason.message },
				`BOLA Detection Check could not verify ${targetUrl} [${baseDetail.test_id}] at the Request Execution stage due to baseline request failing: ${settledA.reason.message}`
			);
		}
		if (settledB.status === 'rejected') {
			return untestableResult(
				targetUrl,
				{ ...baseDetail, reason: settledB.reason.message },
				`BOLA Detection Check could not verify ${targetUrl} [${baseDetail.test_id}] at the Request Execution stage due to main test request failing: ${settledB.reason.message}`
			);
		}

		const responseObjectA = settledA.value;
		const responseObjectB = settledB.value;

		if (responseObjectA.statusCode !== 200) {
			return untestableResult(
				targetUrl,
				{ ...baseDetail, reason: 'Invalid baseline check', baselineStatusCode: responseObjectA.statusCode },
				`BOLA Detection Check could not verify ${targetUrl} [${baseDetail.test_id}]: baseline request returned ${responseObjectA.statusCode}; ${baselineHint(responseObjectA.statusCode)}`
			);
		}

		if (responseObjectB.statusCode === 401) {
			return untestableResult(
				targetUrl,
				{ ...baseDetail, statusCode: 401, reason: 'attacker token rejected as unauthenticated' },
				`BOLA Detection Check could not conclude on ${targetUrl} [${baseDetail.test_id}]: the attacker request returned 401, meaning TOKEN_B was rejected as unauthenticated (possibly expired or invalid), which does not show the object is access-controlled. Refresh TOKEN_B and re-run.`
			);
		}

		if (responseObjectB.statusCode === 403) {
			return untestableResult(
				targetUrl,
				{ ...baseDetail, statusCode: responseObjectB.statusCode },
				`Object is properly gated (403) [${baseDetail.test_id}]`
			);
		}

		if (responseObjectB.statusCode === 404) {
			return untestableResult(
				targetUrl,
				{ ...baseDetail, statusCode: responseObjectB.statusCode },
				`The object either doesn't exist or is properly gated using 404-instead-of-403 [${baseDetail.test_id}]`
			);
		}

		if (responseObjectB.statusCode !== 200) {
			return untestableResult(
				targetUrl,
				{ ...baseDetail, statusCode: responseObjectB.statusCode },
				`BOLA Detection Check could not classify ${targetUrl} [${baseDetail.test_id}]: attacker request returned unexpected status ${responseObjectB.statusCode}`
			);
		}

		const comparisonAB = compareResponses(responseObjectA, responseObjectB);
		if (comparisonAB.result !== COMPARISON.MATCH) {
			return untestableResult(
				targetUrl,
				{ ...baseDetail, comparison: comparisonAB },
				`BOLA Detection Check could not confirm ${targetUrl} [${baseDetail.test_id}]: attacker response could not be matched to the baseline`
			);
		}

		let responseObjectC;
		try {
			responseObjectC = await makeRequest(targetUrl, endpoint.http_method);
		} catch (error) {
			return vulnerableFinding(
				targetUrl,
				baseDetail,
				'Tentative',
				{ comparison: comparisonAB, controlError: error.message },
				`. The attacker token's response matched the owner's baseline, but the unauthenticated control request failed to execute (${error.message}), so this is reported at reduced confidence pending a retest.`
			);
		}

		if (responseObjectC.statusCode === 401 || responseObjectC.statusCode === 403 || responseObjectC.statusCode === 404) {
			const confidence = comparisonAB.mode === 'json' ? 'Certain' : 'Firm';
			return vulnerableFinding(
				targetUrl,
				baseDetail,
				confidence,
				{ comparison: comparisonAB, controlStatusCode: responseObjectC.statusCode },
				`. The attacker token retrieved content matching the owner's baseline, while an unauthenticated request to the same object was rejected (status ${responseObjectC.statusCode}) — the object is access-controlled, but not per-object.`
			);
		}

		if (responseObjectC.statusCode === 200 && compareResponses(responseObjectA, responseObjectC).result === COMPARISON.MATCH) {
			return untestableResult(
				targetUrl,
				baseDetail,
				`Not a BOLA finding on ${targetUrl} [${baseDetail.test_id}]: the object is also returned without any token, so it was never access-controlled (see Missing Authentication Detection)`
			);
		}

		return untestableResult(
			targetUrl,
			{ ...baseDetail, controlStatusCode: responseObjectC.statusCode },
			`BOLA Detection Check could not classify ${targetUrl} [${baseDetail.test_id}]: unauthenticated control request returned unexpected status ${responseObjectC.statusCode}`
		);
	});

	const returnedResults = await Promise.allSettled(result);

	return returnedResults.reduce((acc, request) => {
		if (request.status === 'fulfilled') {
			acc.push(request.value);
		}
		if (request.status === 'rejected') {
			acc.push(untestableResult(
				url,
				{ reason: 'unexpected internal error' },
				'BOLA Detection Check encountered an unexpected internal error while processing a config entry.'
			));
		}
		return acc;
	}, []);
}