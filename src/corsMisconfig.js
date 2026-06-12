import https from 'node:https';

function generateTestURL(url) {
	const myURL1 = new URL(url);
	const myURL2 = new URL(url);
	const myURL3 = new URL(url);

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

	const resultPromises = testScenarios.map(newURL => {

		return new Promise((resolve, reject) => {

			const options = {
				hostname: originalURL.hostname,
				path: originalURL.pathname + originalURL.search,
				method: 'GET',
				headers: {
					'Origin': newURL.originHeader,
				}
			}
	
			const req = https.request(options, (res) => {
				const resultHeaders = res.headers;
				if (resultHeaders?.['access-control-allow-origin'] === '*') {
					resolve({
						header: 'access-control-allow-origin',
						status: 'Present',
						value: '*',
						originUsed: newURL.originHeader,
						severity: 'High'
					});
				}
				else if (resultHeaders?.['access-control-allow-origin'] === newURL.originHeader && resultHeaders?.['access-control-allow-credentials'] === 'true') {
					resolve({
						header: 'access-control-allow-origin',
						status: 'Present',
						value: 'true',
						originUsed: newURL.originHeader,
						severity: 'Critical'
					})
				}
				else if (resultHeaders?.['access-control-allow-origin'] === newURL.originHeader) {
					resolve({
						header: 'access-control-allow-origin',
						status: 'Present',
						value: originalURL.origin,
						originUsed: newURL.originHeader,
						severity: 'High'
					})
				}
				else if (!resultHeaders?.['access-control-allow-origin'] && !resultHeaders?.['access-control-allow-credentials']){
					resolve({
						headers: 'access-control-allow-origin, access-control-allow-credentials',
						status: 'Absent',
						value: 'None',
						originUsed: newURL.originHeader,
						severity: 'None'
					})
				}
				else{
					resolve({
						header: 'access-control-allow-origin',
						status: resultHeaders?.['access-control-allow-origin'] ? 'Present (Secure/Unmatched)' : Absent,
						value: resultHeaders?.['access-control-allow-origin'] || 'None',
						originUsed: newURL.originHeader,
						severity: 'None'
					});
				}
			});
	
			req.on('error', reject);
	
			req.end();
		})
	});

	return Promise.all(resultPromises);
}