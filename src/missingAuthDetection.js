import { makeRequest } from "./requestHelper.js";

export async function checkMissingAuth(url, pathMethod) {

	const possibleMethodSeverities = {
		GET: 'Medium/High',
		POST: 'High',
		PUT: 'High',
		DELETE: 'High'
	};

	const result = pathMethod.map(async (input) => {
		const newUrl = new URL(input.path, url);
	
		const responseObject = await makeRequest(newUrl.href, input.method);
	
		if (responseObject.statusCode >= 200 && responseObject.statusCode <= 204) {
			return {
				endpoint: newUrl.href,
				method: input.method,
				statusCode: responseObject.statusCode,
				status: 'Reachable',
				severity: possibleMethodSeverities[input.method]
			};
		}
		else {
			return null;
		}
	})

	const returnedResults = await Promise.allSettled(result);

	return returnedResults.reduce((acc, request) => {
		if (request.status === 'fulfilled' && request.value) {
			acc.push(request.value);
		}

		return acc;
	}, []);
}

