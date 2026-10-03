import 'dotenv/config';
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
import { checkBola } from './src/bola.js';
import { generateReport } from './src/reportGenerator.js';
import { displayResults } from './src/reportGenerator.js';
import { writeJsonReport } from './src/reportGenerator.js';
import { preflightCheck } from './src/preflightCheck.js';
import fs from 'node:fs';

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

const rawArgs = process.argv.slice(3);
if (rawArgs.includes('--bola-config')) {
	console.log('Use --bola-config=<file> with an equals sign. The space-separated form is not supported.');
	process.exit(2);
}
const bolaConfigArg = rawArgs.find(arg => arg.startsWith('--bola-config='));
const bolaConfigPath = bolaConfigArg ? bolaConfigArg.split('=')[1] : null;
const cliArgs = rawArgs.filter(arg => !arg.startsWith('--bola-config='));

if (cliArgs.length === 0) {
	console.log(`No path:method provided - Defaulting to Base URL and 'GET' method`);
}

pathMethod.push(...cliArgs.map(arg => {
	const [path, method] = arg.split(':');
	return { path, method, source: 'user-specified' };
}))

let bolaConfig;
if (bolaConfigPath) {
	let rawConfig;
	try {
		rawConfig = fs.readFileSync(bolaConfigPath, 'utf-8');
	} catch (error) {
		console.log(`Could not read --bola-config file at ${bolaConfigPath}: ${error.message}`);
		process.exit(2);
	}

	let parsedConfig;
	try {
		parsedConfig = JSON.parse(rawConfig);
	} catch (error) {
		console.log(`--bola-config file at ${bolaConfigPath} is not valid JSON: ${error.message}`);
		process.exit(2);
	}

	if (Array.isArray(parsedConfig)) {
		bolaConfig = parsedConfig;
	}
	else if (typeof parsedConfig === 'object' && parsedConfig !== null) {
		bolaConfig = [parsedConfig];
	}
	else {
		console.log(`--bola-config file at ${bolaConfigPath} must contain a JSON object or an array of objects`);
		process.exit(2);
	}

	if (!process.env.TOKEN_A || !process.env.TOKEN_B) {
		console.log('--bola-config was provided, but TOKEN_A and TOKEN_B environment variables must both be set to run the BOLA check.');
		process.exit(2);
	}
}

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
		'Reflected XSS in Cookie': xssCookieCheck(url, pathMethod),
		'BOLA/IDOR Check': checkBola(url, bolaConfig, { tokenA: process.env.TOKEN_A, tokenB: process.env.TOKEN_B })
	};

	const resultCheckNames = Object.keys(result);
	const resultPromises = Object.values(result);

	const resolvedResult = await Promise.allSettled(resultPromises);

	const { bySeverity, untestable, toolErrors } = generateReport(resolvedResult, resultCheckNames);
	displayResults(bySeverity, untestable, toolErrors, inputUrl);

	const jsonWriteResult = writeJsonReport(bySeverity, untestable, toolErrors, inputUrl);

	if (bySeverity.Critical.length > 0 || bySeverity.High.length > 0){
		process.exit(1);
	}
}

main(inputUrl);