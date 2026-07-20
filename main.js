import { checkVerboseErrors } from './src/errorVerbose.js';
import { checkHeaders } from './src/missingHeaders.js';
import { checkCorsMisconfig } from './src/corsMisconfig.js';
import { checkMethodExposure } from './src/httpMethodsExposure.js';
import { checkMissingAuth } from './src/missingAuthDetection.js';
import { requestHandler } from './src/rateLimitCheck.js';
import { makeMultipleRequestsUsingQuerys } from './src/xssCheck.js';
import { checkForHttps } from './src/httpsCheck.js';
import { generateReport } from './src/reportGenerator.js';

const inputUrl = process.argv[2];

const pathMethod = [];
pathMethod.push({
	path: '/',
	method: 'GET',
	source: 'default-base-check'
})

if (!inputUrl) {
	console.log('Please provide a URL');
	console.log('Proper Syntax for running the tool\n node main.js url');
	process.exit(1);
}

if (!process.argv[3]) {
	console.log(`No path:method provided - Defaulting to Base URL and 'GET' method`);
}

pathMethod.push(...process.argv.slice(3).map(arg => {
	const [path, method] = arg.split(':');
	return { path, method, source: 'user-specified' };
}))

async function main(url) {

	const result = {
		'HTTPS Check': checkForHttps(url),
		'Security Headers Check': checkHeaders(url, pathMethod),
		'Verbose Error': checkVerboseErrors(url, pathMethod),
		'CORS Misconfiguration': checkCorsMisconfig(url, pathMethod),
		'HTTP Methods Exposure': checkMethodExposure(url, pathMethod),
		'Missing Authentication Detection': checkMissingAuth(url, pathMethod),
		'Rate Limit Check': requestHandler(url, pathMethod),
		'XSS Check': makeMultipleRequestsUsingQuerys(url, pathMethod)
	};

	const resultCheckNames = Object.keys(result);
	const resultPromises = Object.values(result);

	const resolvedResult = await Promise.allSettled(resultPromises);


	// --- TEMPORARY INSTRUMENTATION START ---
	const debugTargets = [
		'checkCorsMisconfig', 'checkMethodExposure', 'makeMultipleRequestsUsingQuerys',
		'CORS', 'HTTP Methods Exposure', 'XSS Check'
	];

	resolvedResult.forEach((res, index) => {
		const checkName = resultCheckNames[index];

		// Only log if the checkName matches one of our targets
		const isTarget = debugTargets.some(target => checkName.includes(target));

		if (isTarget) {
			console.log(`\n[DEBUG] ---> Check: ${checkName}`);
			console.log(`[DEBUG] Status: ${res.status}`);

			if (res.status === 'fulfilled') {
				const val = res.value;
				console.log(`[DEBUG] Is Array?: ${Array.isArray(val)}`);
				console.log(`[DEBUG] Length: ${Array.isArray(val) ? val.length : 'N/A'}`);
				console.dir(val, { depth: null, colors: true });
			} else {
				console.error(`[DEBUG] REJECTED Reason:`, res.reason);
			}
		}
	});
	// --- TEMPORARY INSTRUMENTATION END ---
	

	const generatedReport = generateReport(resolvedResult, resultCheckNames);
	console.dir(generatedReport, { depth: null });
}

main(inputUrl);