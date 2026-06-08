import https from 'node:https';

export async function checkHeaders(url) {
	const result = [];
	
	const requiredHeaders = [
		{ header: 'x-frame-options', severity: 'Medium' },
		{ header: 'x-content-type-options', severity: 'Medium-Low' },
		{ header: 'content-security-policy', severity: 'High' },
		{ header: 'strict-transport-security', severity: 'High' }
	];

	return new Promise((resolve, reject) => {
		https.get(url, (res) => {	
			for (const currHeader of requiredHeaders) {
				if (!res.headers[currHeader.header]) {
					result.push({
						endpoint: url,
						header: currHeader.header,
						status: 'Absent',
						severity: currHeader.severity
					});	
				}
			}
			resolve(result);
		}).on('error', reject);
	})
}