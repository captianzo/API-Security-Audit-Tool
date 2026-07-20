import { makeRequest } from "./requestHelper.js";

async function triggerRequest(url, sequenceNumber) {
	const responseObject = makeRequest(url, 'GET')
		.then((result) => {
			result.number = sequenceNumber;
			return result;
		});

	return responseObject;
}

export async function requestHandler(url, pathMethod) {
	const result = [];
	const allowedStatusCodes = [402, 403, 429, 503];

	for (const input of pathMethod) {
		let currentUrlString = `${url}/${input.path}`;

		try {
			const newUrl = new URL(input.path, url);
			currentUrlString = newUrl.href;
		} catch (error) {
			result.push({
				checkName: 'Rate Limit Check',
				endpoint: currentUrlString,
				source: input.source,
				testable: false,
				detail: {
					method: input.method,
					stage: 'url construction',
					reason: error.message
				},
				description: `Rate Limit Check could not verify ${currentUrlString} at the URL Construction stage: ${error.message}`
			})
			continue;
		}
		const requests = [];

		for (let i = 1; i <= 100; i++) {
			requests.push(triggerRequest(currentUrlString, i));
		}

		const resolvedRequests = Promise.allSettled(requests);

		const filteredRequests = (await resolvedRequests).filter(request => allowedStatusCodes.includes(request?.value?.statusCode))

		if (filteredRequests.length === 0) {
			result.push({
				checkName: 'Rate Limit Check',
				endpoint: currentUrlString,
				source: input.source,
				severity: 'Critical',
				detail: {
					rateLimiting: 'Disabled',
				},
				description: 'No rate limiting was detected. The endpoint successfully processed a high volume of rapid requests without blocking.',
				remediation: 'Implement rate limiting (returning HTTP 429) per IP or user session to prevent denial-of-service, automated scraping, and brute-force attacks.'
			})
			continue;
		}

		const minElement = filteredRequests.reduce((min, current) => {
			return current.value.number < min.value.number ? current : min;
		});

		if (minElement.value.number >= 1 && minElement.value.number <= 20) {
			continue;
		}

		else if (minElement.value.number >= 21 && minElement.value.number <= 50) {
			result.push({
				checkName: 'Rate Limit Check',
				endpoint: currentUrlString,
				source: input.source,
				severity: 'Low',
				detail: {
					rateLimiting: 'Enabled',
					statusCode: minElement.value.statusCode,
					requestNumber: minElement.value.number,
				},
				description: 'Rate limiting is active but allows moderate bursting (up to 50 requests). This is generally safe for standard APIs, but poses a risk if this endpoint handles authentication.',
				remediation: 'Review the endpoint context. If it handles sensitive actions like login or password reset, tighten the limit to under 10 requests per minute. Otherwise, the current burst limit is acceptable.'
			})
		}
		else {
			result.push({
				checkName: 'Rate Limit Check',
				endpoint: currentUrlString,
				source: input.source,
				severity: 'High',
				detail: {
					rateLimiting: 'Enabled',
					statusCode: minElement.value.statusCode,
					requestNumber: minElement.value.number,
				},
				description: 'Rate limiting is active but highly permissive, only blocking after 50+ rapid requests. This still allows attackers to sustain high-volume automated attacks and scraping.',
				remediation: 'Sharply reduce the allowed request threshold. Apply strict limits (e.g., 5-10 requests/minute) for sensitive endpoints and moderate limits (e.g., 30 requests/minute) for general data access.'
			})
		}
	}

	return result;
}