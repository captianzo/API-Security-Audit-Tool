import { makeRequest } from './requestHelper.js';

export async function checkHeaders(url) {
	const result = [];

	const requiredHeaders = [
		{ header: 'x-frame-options', severity: 'Medium' },
		{ header: 'x-content-type-options', severity: 'Medium-Low' },
		{ header: 'content-security-policy', severity: 'High' },
		{ header: 'strict-transport-security', severity: 'High' }
	];

	const responseObject = await makeRequest(url, 'GET');

	for (const currHeader of requiredHeaders) {
		if (!responseObject.headers[currHeader.header]) {
			result.push({
				endpoint: url,
				header: currHeader.header,
				status: 'Absent',
				severity: currHeader.severity
			});
		}
	}

	return result;
}