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
			}
		}];
	}
	return null;
}