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
				}
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
				}
			})
			continue;
		}

		const minElement = filteredRequests.reduce((min, current) => {
			return current.value.number < min.value.number ? current : min;
		});

		if (minElement.value.number >= 1 && minElement.value.number <= 20) {
			// result.push({
			// 	checkName: 'Rate Limit Check',
			// 	endpoint: currentUrlString,
			// 	source: input.source,
			// 	severity: 'None',
			// 	detail: {
			// 		rateLimiting: 'Enabled',
			// 		statusCode: minElement.value.statusCode,
			// 		requestNumber: minElement.value.number,
			// 	}
			// })
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
				}
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
				}
			})
		}
	}

	return result;
}