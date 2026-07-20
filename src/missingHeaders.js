import { makeRequest } from './requestHelper.js';

export async function checkHeaders(url, pathMethod) {
	const result = [];

	const requiredHeaders = [
		{ header: 'x-frame-options', severity: 'Medium' },
		{ header: 'x-content-type-options', severity: 'Medium' },
		{ header: 'content-security-policy', severity: 'High' },
		{ header: 'strict-transport-security', severity: 'High' }
	];

	const missingHeaderDetails = {
		'x-frame-options': {
			description: 'The response does not set X-Frame-Options, allowing the page to be embedded in an iframe on another site. This enables clickjacking, where an attacker overlays invisible UI elements to trick users into performing unintended actions.',
			remediation: 'Set the X-Frame-Options header to DENY or SAMEORIGIN, or use the frame-ancestors directive in a Content-Security-Policy header for more granular control.'
		},
		'x-content-type-options': {
			description: 'The response does not set X-Content-Type-Options, allowing browsers to MIME-sniff the response and interpret it as a different content type than declared. This can let an attacker-supplied file (e.g. disguised as an image) execute as script.',
			remediation: 'Set the X-Content-Type-Options header to "nosniff" so browsers strictly respect the declared Content-Type.'
		},
		'content-security-policy': {
			description: 'The response does not set a Content-Security-Policy header, leaving the browser with no restriction on which sources scripts, styles, or other resources can be loaded from. This significantly increases the impact of any XSS vulnerability, since injected scripts run without restriction.',
			remediation: 'Define a Content-Security-Policy that restricts script, style, and resource origins to trusted sources (e.g. script-src \'self\'), avoiding unsafe-inline and unsafe-eval where possible.'
		},
		'strict-transport-security': {
			description: 'The response does not set Strict-Transport-Security, so browsers do not enforce HTTPS for future visits. This leaves users vulnerable to downgrade attacks or SSL stripping, where an attacker forces the connection back to plain HTTP.',
			remediation: 'Set the Strict-Transport-Security header (e.g. "max-age=63072000; includeSubDomains; preload") so browsers automatically upgrade all future requests to HTTPS.'
		}
	};

	await Promise.all(pathMethod.map(async (input) => {
		let responseObject;
		let currentUrlString = `${url}/${input.path}`

		try {
			const newUrl = new URL(input.path, url);
			currentUrlString = newUrl.href;
		} catch (error) {
			result.push({
				checkName: 'Security Headers Check',
				endpoint: currentUrlString,
				source: input.source,
				testable: false,
				detail: {
					method: input.method,
					stage: 'url construction',
					reason: error.message
				},
				description: `Security Headers Check could not verify ${currentUrlString} at the URL Construction stage: ${error.message}`
			})
			return;
		}

		try {
			responseObject = await makeRequest(currentUrlString, input.method);
			for (const currHeader of requiredHeaders) {
				if (!responseObject.headers[currHeader.header]) {
					result.push({
						checkName: 'Security Headers Check',
						endpoint: currentUrlString,
						source: input.source,
						severity: currHeader.severity,
						detail: {
							header: currHeader.header,
							status: 'Absent',
						},
						description: missingHeaderDetails[currHeader.header].description,
						remediation: missingHeaderDetails[currHeader.header].remediation
					});
				}
			}
		}
		catch (error) {
			result.push({
				checkName: 'Security Headers Check',
				endpoint: currentUrlString,
				source: input.source,
				testable: false,
				detail: {
					method: input.method,
					stage: 'response capturing',
					reason: error.message
				},
				description: `Security Headers Check could not verify ${currentUrlString} at the Response Capturing stage: ${error.message}`
			})
		}
	}));

	return result;
}