import https from 'node:https';

export async function makeRequest(requestObjects) {

	const possibleMethodSeverities = {
		GET: 'Medium/High',
		POST: 'High',
		PUT: 'High',
		DELETE: 'High'
	};

	const resolvedRequests = requestObjects.map(request => {

		const url = new URL(request.endpoint);

		return new Promise((resolve, reject) => {

			const options = {
				hostname: url.hostname,
				path: url.pathname + url.search,
				method: request.method,
				headers: {}
			}

			if (request.method !== 'GET'){
				options.headers['Content-Length'] = Buffer.byteLength(request.body);
				options.headers['Content-Type'] = request.contentType;
			}

			const req = https.request(options, (res) => {
				// console.log(res.statusCode);
				if (res.statusCode >= 200 && res.statusCode <= 204) {
					resolve({
						endpoint: url.href,
						method: request.method,
						statusCode: res.statusCode,
						status: 'Reachable',
						severity: possibleMethodSeverities[request.method]
					});
				}
				else {
					resolve([]);
				}
			});

			req.on('error', reject);

			if (request.method !== 'GET'){
				req.write(request.body);
			}

			req.end();
		});
	});

	return (await Promise.all(resolvedRequests)).flat();
}

