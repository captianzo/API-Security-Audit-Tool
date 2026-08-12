import http from 'node:http';
import https from 'node:https';

const PREFLIGHT_TIMEOUT_MS = 3000;

export async function preflightCheck(url) {
	return new Promise((resolve) => {
		const urlObject = new URL(url);

		let protocol = urlObject.protocol === 'https:' ? https : http;

		let options = {
			hostname: urlObject.hostname,
			port: urlObject.port || (urlObject.protocol === 'https:' ? 443 : 80),
			path: urlObject.pathname + urlObject.search,
			method: 'HEAD'
		};

		let settled = false;
		let timedOut = false;

		const req = protocol.request(options, (res) => {
			settled = true;
			// stop watching this socket, response received
			req.setTimeout(0);

			resolve({
				exists: true,
				statusCode: res.statusCode
			});

			// body for a preflight check doesn't matter so drained and discarded
			res.resume();
		});

		req.setTimeout(PREFLIGHT_TIMEOUT_MS, () => {
			if (settled) return; // response already came in, ignore stray timeout
			settled = true;
			timedOut = true;
			req.destroy(); // triggers 'error' below
		});

		req.on('error', (err) => {
			if (settled && !timedOut) return; // already resolved via 'response', nothing to do

			if (timedOut) {
				// this error was caused by req.destroy() above, not a real network failure
				resolve({
					exists: false,
					reason: 'timeout',
					message: `Request timed out after ${PREFLIGHT_TIMEOUT_MS}ms`
				});
			} else {
				// genuine network-level failure (DNS, connection refused, TLS, etc.)
				settled = true;
				resolve({
					exists: false,
					reason: 'network-error',
					code: err.code,
					message: err.message
				});
			}
		});

		req.end();
	});
}