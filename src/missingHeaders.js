import { makeRequest } from './requestHelper.js';

export async function checkHeaders(url, pathMethod) {
	const result = [];

	const requiredHeaders = [
		{ header: 'x-frame-options', severity: 'Medium' },
		{ header: 'x-content-type-options', severity: 'Medium' },
		{ header: 'content-security-policy', severity: 'High' },
		{ header: 'strict-transport-security', severity: 'High' }
	];

	await Promise.all(pathMethod.map(async (input) => {
		let responseObject;
		let currentUrlString = `${url}/${input.path}`
		
		try {
			const newUrl = new URL(input.path, url);
			currentUrlString = newUrl.href;
		} catch (error) {
			result.push({
                checkName: 'Missing Security Headers',
                endpoint: currentUrlString,
				source: input.source,
                testable: false,
                detail: {
					method: input.method,
                    stage: 'url construction',
                    reason: error.message
                }
            })
			return;
		}

		try {
			responseObject = await makeRequest(currentUrlString, input.method);
			for (const currHeader of requiredHeaders) {
				if (!responseObject.headers[currHeader.header]) {
					result.push({
						checkName: 'Missing Security Headers',
						endpoint: currentUrlString,
						source: input.source,
						severity: currHeader.severity,
						detail: {
							header: currHeader.header,
							status: 'Absent',
						}
					});
				}
			}
		}
		catch (error) {
			result.push({
				checkName: 'Missing Security Headers',
				endpoint: currentUrlString,
				source: input.source,
				testable: false,
				detail: {
					method: input.method,
					stage: 'header fetch',
					reason: error.message
				}
			})
		}
	}));

	return result;
}