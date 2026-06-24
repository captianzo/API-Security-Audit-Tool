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
	
	for (const {path, method} of pathMethod){

		const pathRequests = flatWordlist.map(async (newParam) => {
	
			let reflectedInHeaders = false;
			const urlObject = new URL(url);

			urlObject.pathname = path;
			urlObject.searchParams.append(newParam, payload);
			
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

			if (reflectedInBody){
				severity = 'High/Critical';
			}
			else if (reflectedInHeaders){
				severity = 'Medium/High';
			}

			return {
				endpoint: urlObject.href,
				parameter: newParam,
				statusCode: responseObject.statusCode,
				reflectedInHeaders,
				reflectedInBody,
				severity: severity
			};
		});

		allPromises.push(...pathRequests);
	}

	const allSettledRequests = await Promise.allSettled(allPromises);

	return allSettledRequests.reduce((acc, request) => {
		if (request.status === 'fulfilled' && (request.value.reflectedInHeaders || request.value.reflectedInBody)) {
			acc.push(request.value);
		}

		return acc;
	}, []);
}