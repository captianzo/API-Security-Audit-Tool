function convertCamelCase(text) {
	let newText = text[0].toUpperCase() + text.slice(1);
	return newText.replace(/([A-Z])/g, ' $1').trim();
}

let string = 'camelCase';
console.log(convertCamelCase(string));