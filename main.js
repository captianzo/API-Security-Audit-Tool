import { checkVerboseErrors } from './src/errorVerbose.js';
import { checkHeaders } from './src/missingHeaders.js';
import { checkCorsMisconfig } from './src/corsMisconfig.js';
import { checkMethodExposure } from './src/httpMethodsExposure.js';
import { checkMissingAuth } from './src/missingAuthDetection.js';
import { requestHandler } from './src/rateLimitCheck.js';
import { xssQueryCheck } from './src/xssCheck.js';
import { xssHeaderCheck } from './src/xssCheck.js';
import { xssCookieCheck } from './src/xssCheck.js';
import { checkForHttps } from './src/httpsCheck.js';
import { generateReport } from './src/reportGenerator.js';
import { displayResults } from './src/reportGenerator.js';
import { writeJsonReport } from './src/reportGenerator.js';
import { preflightCheck } from './src/preflightCheck.js';

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
	process.exit(2);
}

if (!process.argv[3]) {
	console.log(`No path:method provided - Defaulting to Base URL and 'GET' method`);
}

pathMethod.push(...process.argv.slice(3).map(arg => {
	const [path, method] = arg.split(':');
	return { path, method, source: 'user-specified' };
}))

async function main(url) {

	const preflightResult = await preflightCheck(url);
	if (!preflightResult.exists) {
		console.log(`Preflight check failed: ${preflightResult.message}`);
		console.log(`Reason: ${preflightResult.reason}`);
		process.exit(2);
	}

	const result = {
		'HTTPS Check': checkForHttps(url),
		'Security Headers Check': checkHeaders(url, pathMethod),
		'Verbose Error': checkVerboseErrors(url, pathMethod),
		'CORS Misconfiguration': checkCorsMisconfig(url, pathMethod),
		'HTTP Methods Exposure': checkMethodExposure(url, pathMethod),
		'Missing Authentication Detection': checkMissingAuth(url, pathMethod),
		'Rate Limit Check': requestHandler(url, pathMethod),
		'Reflected XSS in Query': xssQueryCheck(url, pathMethod),
		'Reflected XSS in Header': xssHeaderCheck(url, pathMethod),
		'Reflected XSS in Cookie': xssCookieCheck(url, pathMethod)
	};

	const resultCheckNames = Object.keys(result);
	const resultPromises = Object.values(result);

	const resolvedResult = await Promise.allSettled(resultPromises);

	const { bySeverity, untestable, toolErrors } = generateReport(resolvedResult, resultCheckNames);
	displayResults(bySeverity, untestable, toolErrors, inputUrl);

	// used later for CI/CD exit-code logic
	const jsonWriteResult = writeJsonReport(bySeverity, untestable, toolErrors, inputUrl);

	if (bySeverity.Critical.length > 0 || bySeverity.High.length > 0){
		process.exit(1);
	}
}

main(inputUrl);