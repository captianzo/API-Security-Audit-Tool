import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

export async function collectEndpoints() {
	const rl = readline.createInterface({ input, output });
	const requestObjects = [];

	console.log('Please enter three endpoints\n');

	for (let i = 1; i <= 3; i++) {

		const validMethods = ['GET', 'POST', 'PUT', 'DELETE'];

		console.log(`Request [${i}]`);

		const endpoint = await rl.question('Enter Endpoint URL: ');
		if (!endpoint.trim()) {
			console.log(`URL can't be empty`);
			continue;
		}

		let method = await rl.question('Enter HTTP Method (GET, POST, PUT, DELETE): ');
		method = method.trim().toUpperCase();

		let body = '';

		if (method !== 'GET') {
			body = await rl.question('Enter the body for the request: ');
		}

		if (!validMethods.includes(method)) {
			console.log('Invalid Method! Defaulting to GET\n');
			method = 'GET';
		}

		if (method === 'GET'){
			requestObjects.push({
				endpoint: endpoint.trim(),
				method: method
			});
		}
		else{
			requestObjects.push({
				endpoint: endpoint.trim(),
				method: method,
				body: body.trim(),
				contentType: 'application/json'
			});
		}
	}

	rl.close();

	return requestObjects;
}