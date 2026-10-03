export function collectKeys(value, collectedKeys = []) {
	if (value === null || value === undefined) {
		return collectedKeys;
	}

	if (Array.isArray(value)) {
		for (const element of value) {
			collectKeys(element, collectedKeys);
		}
	}
	else if (typeof value === 'object') {
		const keys = Object.keys(value);
		for (const key of keys) {
			collectedKeys.push(key);
			collectKeys(value[key], collectedKeys);
		}
	}

	return collectedKeys;
}