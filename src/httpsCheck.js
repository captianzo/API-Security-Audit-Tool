export async function checkForHttps(url){
	const urlObject = new URL(url);

	if (urlObject.protocol !== 'https:'){
		return [{
			checkName: 'HTTPS Check',
			endpoint: urlObject.href,
			source: 'default-base-check',
			severity: 'Critical',
			detail: {
				protocol: urlObject.protocol,
			},
			description: 'The endpoint is served over HTTP instead of HTTPS, exposing transmitted data to interception.',
			remediation: 'Obtain a TLS certificate and configure the server to redirect all HTTP traffic to HTTPS. Enable HSTS to prevent future downgrade attempts.'
		}];
	}
	return null;
}