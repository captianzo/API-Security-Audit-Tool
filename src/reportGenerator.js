export function normalizedResults(resolvedResult, resultCheckNames) {
	const fulfilledCheckResults = [];
	const rejectedCheckResults = [];

	for (let i = 0; i < resolvedResult.length; i++) {
		if (resolvedResult[i]?.status === 'rejected') {
			rejectedCheckResults.push({
				checkName: resultCheckNames[i],
				reason: resolvedResult[i].reason
			});
		}
		else {
			if (resolvedResult[i]?.value === null) {
				fulfilledCheckResults.push([]);
			}
			else {
				fulfilledCheckResults.push(resolvedResult[i].value);
			}
		}
	}

	const flatFulfilledCheckResults = fulfilledCheckResults.flat();
	return {flatFulfilledCheckResults, rejectedCheckResults};
}

export function segregateSeverityAndUntestable(flatFulfilledCheckResults, rejectedCheckResults) {
	const bySeverity = {
		Critical: [],
		High: [],
		Medium: [],
		Low: []
	};
	const untestable = {};
	const toolErrors = {};

	for (let i = 0; i < flatFulfilledCheckResults.length; i++) {
		const currentResultObject = flatFulfilledCheckResults[i];
		if (Object.hasOwn(currentResultObject, 'testable')) {
			if (!untestable[currentResultObject.checkName]) {
				untestable[currentResultObject.checkName] = [];
			}
			untestable[currentResultObject.checkName].push(currentResultObject);
		}
		else {
			const currentSeverity = currentResultObject.severity;
			bySeverity[currentSeverity].push(currentResultObject);
		}
	}

	for (let i = 0; i < rejectedCheckResults.length; i++) {
		const currentResultObject = rejectedCheckResults[i];
		if (!toolErrors[currentResultObject.checkName]) {
			toolErrors[currentResultObject.checkName] = [];
		}
		toolErrors[currentResultObject.checkName].push(currentResultObject.reason);
	}

	return {bySeverity, untestable, toolErrors};
}

export function generateReport(resolvedResult, resultCheckNames) {
	const { flatFulfilledCheckResults, rejectedCheckResults } = normalizedResults(resolvedResult, resultCheckNames);
	return segregateSeverityAndUntestable(flatFulfilledCheckResults, rejectedCheckResults);
}