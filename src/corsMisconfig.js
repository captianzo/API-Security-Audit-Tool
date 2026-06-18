import { makeRequest } from "./requestHelper.js";

function generateTestURL(url) {
	const myURL1 = new URL(url);
	const myURL2 = new URL(url);

	const baseHostname = myURL2.hostname;

	const parts = myURL1.hostname.split('.');
	const tld = parts.pop();
	myURL1.hostname = `${parts.join('.')}.evil.${tld}`;

	myURL2.hostname = `evil-${baseHostname}`;

	return [
		{
			originHeader: myURL1.origin
		},
		{
			originHeader: myURL2.origin
		},
		{
			originHeader: 'null'
		}
	];
}

export async function checkCorsMisconfig(url) {

	const testScenarios = generateTestURL(url);

	const originalURL = new URL(url);

	const resultPromises = testScenarios.map(async (newURL) => {

		const responseObject = await makeRequest(url, 'GET', { 'Origin': newURL.originHeader });

		if (responseObject.headers?.['access-control-allow-origin'] === '*') {
			return({
				header: 'access-control-allow-origin',
				status: 'Present',
				value: '*',
				originUsed: newURL.originHeader,
				severity: 'High'
			});
		}
		else if (responseObject.headers?.['access-control-allow-origin'] === newURL.originHeader && responseObject.headers?.['access-control-allow-credentials'] === 'true') {
			return({
				header: 'access-control-allow-origin',
				status: 'Present',
				value: 'true',
				originUsed: newURL.originHeader,
				severity: 'Critical'
			})
		}
		else if (responseObject.headers?.['access-control-allow-origin'] === newURL.originHeader) {
			return({
				header: 'access-control-allow-origin',
				status: 'Present',
				value: originalURL.origin,
				originUsed: newURL.originHeader,
				severity: 'High'
			})
		}
		else if (!responseObject.headers?.['access-control-allow-origin'] && !responseObject.headers?.['access-control-allow-credentials']) {
			return({
				headers: 'access-control-allow-origin, access-control-allow-credentials',
				status: 'Absent',
				value: 'None',
				originUsed: newURL.originHeader,
				severity: 'None'
			})
		}
		else {
			return({
				header: 'access-control-allow-origin',
				status: responseObject.headers?.['access-control-allow-origin'] ? 'Present (Secure/Unmatched)' : Absent,
				value: responseObject.headers?.['access-control-allow-origin'] || 'None',
				originUsed: newURL.originHeader,
				severity: 'None'
			});
		}
	})

	return Promise.all(resultPromises);
}