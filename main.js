import { checkVerboseErrors } from './src/errorVerbose.js';
import { checkHeaders } from './src/missingHeaders.js';
import { checkCorsMisconfig } from './src/corsMisconfig.js';
import { checkMethodExposure } from './src/httpMethodsExposure.js';

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
	const result = [
		checkHeaders(url),
		checkVerboseErrors(url),
		checkCorsMisconfig(url),
		checkMethodExposure(url)
	];

	Promise.all(result).then(resolvedResult => {
		console.log('\nREQUEST HEADERS SECURITY REPORT\n\n', resolvedResult[0]);
		console.log('\nVERBOSE ERROR SECURITY REPORT\n\n', resolvedResult[1]);
		console.log('\nCORS MISCONFIGURATION SECURITY REPORT\n\n', resolvedResult[2]);
		console.log('\nHTTP METHODS EXPOSURE SECURITY REPORT\n\n', resolvedResult[3]);
	})
	.catch(err => {
		console.error(err);
	})
}

main(url.href);