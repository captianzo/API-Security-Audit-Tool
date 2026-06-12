import { checkVerboseErrors } from './src/errorVerbose.js';
import { checkHeaders } from './src/missingHeaders.js';
import { checkCorsMisconfig } from './src/corsMisconfig.js';
import { checkMethodExposure } from './src/httpMethodsExposure.js';
import { makeRequest } from './src/missingAuthDetection.js';
import { collectEndpoints } from './src/endpointCollection.js';
import { requestHandler } from './src/rateLimitCheck.js';

const inputUrl = process.argv[2];

if (!inputUrl) {
	console.log('Please provide a URL');
	console.log('Proper Syntax for running the tool\n node main.js url');
	process.exit(1);
}

const url = new URL(inputUrl);

if (url.protocol !== 'https:') {
	console.log('Using insecure HTTP, please make sure the provided link uses HTTPS');
	process.exit(1);
}


async function main(url) {
	const inputEndpointsForAuthCheck = await collectEndpoints();

	const result = {
		'RESPONSE HEADERS': checkHeaders(url),
		'VERBOSE ERROR': checkVerboseErrors(url),
		'CORS MISCONFIGURATION': checkCorsMisconfig(url),
		'HTTP METHODS EXPOSURE': checkMethodExposure(url),
		'MISSING AUTHENTICATION ON ENDPOINTS': makeRequest(inputEndpointsForAuthCheck),
		'MISSING RATE LIMITING': requestHandler(url)
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

main(url.href);