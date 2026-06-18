import http from 'node:http';
import https from 'node:https';

export async function makeRequest(url, method, headers = {}, body = null) {
	return new Promise ((resolve, reject) => {
		const urlObject = new URL(url);
	
		let protocol = http;
		let chunks = [];
	
		if (urlObject.protocol === 'http:'){
			protocol = http;
		}
		else{
			protocol = https;
		}
	
		let options = {
			hostname: urlObject.hostname,
			port: urlObject.port || (urlObject.protocol === 'https:' ? 443 : 80),
			path: urlObject.pathname + urlObject.search,
			method: method,
			headers: headers
		}
	
		const req = protocol.request(options, (res) => {
			res.on('data', (chunk) => {
				chunks.push(chunk);
			})

			res.on('end', () => {
				const responseBody = Buffer.concat(chunks).toString();

				resolve({
					statusCode: res.statusCode,
					headers: res.headers,
					body: responseBody
				})
			})
		})

		if (body){
			req.write(body);
		}

		req.on('error', reject);

		req.end();
	})
}