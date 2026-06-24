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
		const newUrl = new URL(input.path, url);
		const requests = [];

		for (let i = 1; i <= 100; i++) {
			requests.push(triggerRequest(newUrl.href, i));
		}

		const resolvedRequests = Promise.allSettled(requests);

		const filteredRequests = (await resolvedRequests).filter(request => allowedStatusCodes.includes(request?.value?.statusCode))

		if (filteredRequests.length === 0) {
			result.push({
				endpoint: newUrl.href,
				rateLimiting: 'Disabled',
				severity: 'Critical'
			})
			continue;
		}

		const minElement = filteredRequests.reduce((min, current) => {
			return current.value.number < min.value.number ? current : min;
		});

		if (minElement.value.number >= 1 && minElement.value.number <= 20) {
			return null;
		}

		else if (minElement.value.number >= 21 && minElement.value.number <= 50) {
			result.push({
				endpoint: newUrl.href,
				rateLimiting: 'Enabled',
				statusCode: minElement.value.statusCode,
				requestNumber: minElement.value.number,
				severity: 'Low'
			})
		}
		else {
			result.push({
				endpoint: newUrl.href,
				rateLimiting: 'Enabled',
				statusCode: minElement.value.statusCode,
				requestNumber: minElement.value.number,
				severity: 'High'
			})
		}
	}

	return result;
}