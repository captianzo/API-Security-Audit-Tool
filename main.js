import { checkVerboseErrors } from './src/errorVerbose.js';
import { checkHeaders } from './src/missingHeaders.js';
import { checkCorsMisconfig } from './src/corsMisconfig.js';
import { checkMethodExposure } from './src/httpMethodsExposure.js';
import { checkMissingAuth } from './src/missingAuthDetection.js';
import { requestHandler } from './src/rateLimitCheck.js';
import { makeMultipleRequestsUsingQuerys } from './src/xssCheck.js';
import { checkForHttps } from './src/httpsCheck.js';
import { generateReport } from './src/reportGenerator.js';
import { displayResults } from './src/reportGenerator.js';

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

	const {bySeverity, untestable, toolErrors} = generateReport(resolvedResult, resultCheckNames);
	// console.dir(generatedReport, { depth: null });
	displayResults(bySeverity, untestable, toolErrors, inputUrl);
}

main(inputUrl);