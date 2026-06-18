import { makeRequest } from "./requestHelper.js";

export async function checkVerboseErrors(url) {
	const result = [];

	const errorIndicators = [
		// Stack traces
		{ pattern: 'at Object.', severity: 'Medium' },
		{ pattern: 'at Function.', severity: 'Medium' },

		// Framework disclosure
		{ pattern: 'Express', severity: 'Low' },
		{ pattern: 'Rails', severity: 'Low' },
		{ pattern: 'Django', severity: 'Low' },
		{ pattern: 'Laravel', severity: 'Low' },

		// Database errors
		{ pattern: 'SQL', severity: 'Medium-High' },
		{ pattern: 'syntax error', severity: 'Medium-High' },
		{ pattern: 'ORA-', severity: 'High' },
		{ pattern: 'pg_', severity: 'Medium-High' },

		// Internal paths
		{ pattern: '/home/', severity: 'Medium' },
		{ pattern: '/var/www/', severity: 'Medium' },
		{ pattern: 'C:\\Users\\', severity: 'Medium' },

		// Full HTML error pages
		{ pattern: '<!DOCTYPE html>', severity: 'Low' },
		{ pattern: '</html>', severity: 'Low' }
	];
	const errorRegexIndicators = [
		{
			pattern: /at .*:\d+:\d+/,
			severity: 'Medium'
		}
	];

	const responseObject = await makeRequest(url, 'GET');

	if (responseObject.statusCode >= 400 && responseObject.statusCode <= 599) {
		for (const errMsg of errorIndicators) {
			if (responseObject.body.includes(errMsg.pattern)) {
				// console.log(`Verbose error! Information leak caused due to ${errMsg}`);
				result.push({
					endpoint: url,
					pattern: errMsg.pattern,
					severity: errMsg.severity
				});
			}
		}

		for (const regexIndicator of errorRegexIndicators) {
			if (regexIndicator.pattern.test(responseObject.body)) {
				result.push({
					endpoint: url,
					pattern: regexIndicator.pattern.toString(),
					severity: regexIndicator.severity
				});
			}
		}
	}

	return result;
}