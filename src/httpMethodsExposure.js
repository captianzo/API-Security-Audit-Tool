import https from 'node:https';

function makeOptionsRequest(url) {

	return new Promise((resolve, reject) => {
		const options = {
			hostname: url.hostname,
			path: url.pathname + url.search,
			method: 'OPTIONS'
		}

		const req = https.request(options, (res) => {

			const findings = [];
			const resultHeaders = res.headers;

			if (resultHeaders?.allow) {
				if (resultHeaders.allow.includes('TRACE')) {
					findings.push({
						endpoint: url.href,
						header: 'allow',
						status: 'Present',
						value: 'TRACE',
						severity: 'Medium'
					});
				}
				if (resultHeaders.allow.includes('PUT')) {
					findings.push({
						endpoint: url.href,
						header: 'allow',
						status: 'Present',
						value: 'PUT',
						severity: 'Low'
					});
				}
				if (resultHeaders.allow.includes('DELETE')) {
					findings.push({
						endpoint: url.href,
						header: 'allow',
						status: 'Present',
						value: 'DELETE',
						severity: 'Low'
					});
				}
			}
			resolve(findings);
		})

		req.on('error', reject);

		req.end();
	})
}

function makeTraceRequest(url) {
	return new Promise((resolve, reject) => {
		const options = {
			hostname: url.hostname,
			path: url.pathname + url.search,
			method: 'TRACE'
		}

		const req = https.request(options, (res) => {
			if (res.statusCode === 200) {
				resolve({
					endpoint: url.href,
					header: 'TRACE',
					status: 'Present',
					severity: 'Medium'
				});
			}
			else{
				resolve([]);
			}
		});

		req.on('error', reject);

		req.end();
	})
}

export async function checkMethodExposure(inputUrl) {
	const result = [];
	const url = new URL(inputUrl);

	result.push(makeOptionsRequest(url));
	result.push(makeTraceRequest(url));

	const combinedArrayResult = Promise.all(result);
	return (await combinedArrayResult).flat();
}