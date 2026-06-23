export async function checkForHttps(url){
	const urlObject = new URL(url);

	if (urlObject.protocol !== 'https:'){
		return {
			endpoint: urlObject.href,
			protocol: urlObject.protocol,
			severity: 'Critical'
		};
	}
	else {
		return {
			endpoint: urlObject.href,
			protocol: urlObject.protocol,
			severity: 'None'
		};
	}
}