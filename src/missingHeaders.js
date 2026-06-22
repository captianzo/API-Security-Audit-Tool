import { makeRequest } from './requestHelper.js';

export async function checkHeaders(url, pathMethod) {
	const result = [];

	const requiredHeaders = [
		{ header: 'x-frame-options', severity: 'Medium' },
		{ header: 'x-content-type-options', severity: 'Medium-Low' },
		{ header: 'content-security-policy', severity: 'High' },
		{ header: 'strict-transport-security', severity: 'High' }
	];

	await Promise.all(pathMethod.map(async (input) => {
		const newUrl = new URL(input.path, url);
		let responseObject;

		try {
			responseObject = await makeRequest(newUrl.href, input.method);
			for (const currHeader of requiredHeaders) {
				if (!responseObject.headers[currHeader.header]) {
					result.push({
						endpoint: newUrl.href,
						header: currHeader.header,
						status: 'Absent',
						severity: currHeader.severity
					});
				}
			}
		}
		catch (error) {
			result.push({
				endpoint: newUrl.href,
				method: input.method,
				status: 'Untestable',
				reason: error.message
			})
		}
	}));

	return result;
}