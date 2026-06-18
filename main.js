import { checkVerboseErrors } from './src/errorVerbose.js';
import { checkHeaders } from './src/missingHeaders.js';
import { checkCorsMisconfig } from './src/corsMisconfig.js';
import { checkMethodExposure } from './src/httpMethodsExposure.js';
import { checkMissingAuth } from './src/missingAuthDetection.js';
import { requestHandler } from './src/rateLimitCheck.js';
import { makeMultipleRequestsUsingQuerys } from './src/injectionSurfaces.js';
import { checkForHttps } from './src/httpsCheck.js';

const inputUrl = process.argv[2];

const pathMethod = process.argv.slice(3).map(arg => {
	const [path, method] = arg.split(':');
	return { path, method };
})

if (!inputUrl) {
	console.log('Please provide a URL');
	console.log('Proper Syntax for running the tool\n node main.js url');
	process.exit(1);
}

async function main(url) {

	const result = {
		'MISSING HTTPS PROTOCOL': checkForHttps(url),
		'RESPONSE HEADERS': checkHeaders(url),
		'VERBOSE ERROR': checkVerboseErrors(url),
		'CORS MISCONFIGURATION': checkCorsMisconfig(url),
		'HTTP METHODS EXPOSURE': checkMethodExposure(url),
		'MISSING AUTHENTICATION ON ENDPOINTS': checkMissingAuth(url, pathMethod),
		'MISSING RATE LIMITING': requestHandler(url),
		'CROSS SITE SCRIPTING (XSS)': makeMultipleRequestsUsingQuerys(url)
	};

	const resultCheckNames = Object.keys(result);
	const resultPromises = Object.values(result);

	Promise.allSettled(resultPromises).then(resolvedResult => {
		for (let i = 0; i < resultCheckNames.length; i++){
			if (resolvedResult[i].value === null){
				console.log(resultCheckNames[i], "\n", []);
				continue;
			}
			if (resolvedResult[i].status === 'rejected'){
				console.log('\nERROR PERFORMING CHECK FOR', resultCheckNames[i]);
			}
			else {
				console.log(resultCheckNames[i], "\n", resolvedResult[i].value);
			}
		}
	})
	.catch(err => {
		console.error(err);
	})
}

main(inputUrl);