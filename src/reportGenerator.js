import chalk from 'chalk';
import fs from 'fs';
import url from 'node:url';
import path from 'node:path';

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
	return { flatFulfilledCheckResults, rejectedCheckResults };
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
		toolErrors[currentResultObject.checkName].push({
			checkName: currentResultObject.checkName,
			reason: currentResultObject.reason,
			description: `${currentResultObject.checkName} failed due to: ${currentResultObject.reason.message}`
		});
	}

	return { bySeverity, untestable, toolErrors };
}

export function generateReport(resolvedResult, resultCheckNames) {
	const { flatFulfilledCheckResults, rejectedCheckResults } = normalizedResults(resolvedResult, resultCheckNames);
	return segregateSeverityAndUntestable(flatFulfilledCheckResults, rejectedCheckResults);
}

// Cosmetic helpers (colors, icons, alignment, wrapping)
const DIVIDER_WIDTH = 44;
const WRAP_WIDTH = 70; // characters per line before wrapping description/remediation text
const LABEL_WIDTH = 14; // width of "Endpoint    : " etc, so continuation lines can align under it

// Single source of truth for severity -> color/icon, reused by both the
// summary block and the per-finding detail helper.
const SEVERITY_STYLE = {
	Critical: { color: chalk.bold.red, icon: '🔴' },
	High: { color: chalk.hex('#FF8C00'), icon: '🟠' }, // orange
	Medium: { color: chalk.yellow, icon: '🟡' },
	Low: { color: chalk.gray, icon: '⚪' }
};

function colorForSeverity(severity) {
	return SEVERITY_STYLE[severity]?.color ?? chalk.white;
}

function iconForSeverity(severity) {
	return SEVERITY_STYLE[severity]?.icon ?? '•';
}

// Wraps `text` to WRAP_WIDTH chars per line, indenting continuation lines
// so they align under the label (e.g. "Description : "), and prints it.
function printWrappedField(label, text) {
	const words = String(text).split(' ');
	const lines = [];
	let currentLine = '';

	for (const word of words) {
		if ((currentLine + ' ' + word).trim().length > WRAP_WIDTH) {
			lines.push(currentLine.trim());
			currentLine = word;
		}
		else {
			currentLine = (currentLine + ' ' + word).trim();
		}
	}
	if (currentLine) {
		lines.push(currentLine.trim());
	}

	const paddedLabel = `  ${label}`.padEnd(LABEL_WIDTH + 2) + ': ';
	const continuationIndent = ' '.repeat(paddedLabel.length);

	console.log(paddedLabel + lines[0]);
	for (let i = 1; i < lines.length; i++) {
		console.log(continuationIndent + lines[i]);
	}
}

function divider(char = '=') {
	console.log(chalk.dim(char.repeat(DIVIDER_WIDTH)));
}


// Per-finding display helpers
function severitydisplayHelper(checkName, endpoint, severity, description, remediation) {
	const color = colorForSeverity(severity);
	const icon = iconForSeverity(severity);
	console.log(color.bold(`${icon} [${severity}]`), chalk.cyan.bold(checkName));
	printWrappedField('Endpoint', endpoint);
	printWrappedField('Description', description);
	printWrappedField('Remediation', remediation);
	console.log('');
}

function untestableDisplayHelper(checkName, endpoint, description) {
	console.log(chalk.bold(`❓ [`) + chalk.cyan.bold(checkName) + chalk.bold(`]`));
	printWrappedField('Endpoint', endpoint);
	printWrappedField('Description', description);
	console.log('');
}

function toolErrorDisplayHelper(checkName, description) {
	console.log(chalk.magenta.bold(`⚠️  [`) + chalk.cyan.bold(checkName) + chalk.magenta.bold(`]`));
	printWrappedField('Description', description);
	console.log('');
}

// Helper to count total findings across all keys of an object-of-arrays
// (used for untestable/toolErrors, which are keyed by checkName rather than severity)
function countTotalFindings(groupedObject) {
	let total = 0;
	for (const findings of Object.values(groupedObject)) {
		total += findings.length;
	}
	return total;
}


// Main display function
export function displayResults(bySeverity, untestable, toolErrors, baseUrl) {
	// ---- Header banner ----
	divider();
	console.log(chalk.bold.white(`  API SECURITY AUDIT - ${baseUrl}`));
	divider();
	console.log('');

	// ---- Severity summary block ----
	let totalFindings = 0;
	Object.entries(bySeverity).forEach(([severity, findings]) => {
		totalFindings += findings.length;
		const color = colorForSeverity(severity);
		const icon = iconForSeverity(severity);
		console.log(`  ${icon} ${color.bold(severity.toUpperCase().padEnd(10))} ${chalk.bold(findings.length)}`);
	});
	divider('-');
	console.log(chalk.bold(`  TOTAL      ${totalFindings} findings`));
	divider();
	console.log('');

	// ---- Severity findings detail ----
	Object.entries(bySeverity).forEach(([severity, findings]) => {
		if (!(findings.length > 0)) {
			return;
		}
		findings.forEach(resultObject => {
			severitydisplayHelper(resultObject.checkName, resultObject.endpoint, resultObject.severity, resultObject.description, resultObject.remediation);
		});
	});

	// ---- Untestable section ----
	const totalUntestable = countTotalFindings(untestable);
	if (totalUntestable > 0) {
		divider();
		console.log(chalk.cyan.bold(`  UNTESTABLE  ${totalUntestable}`));
		divider();
		console.log('');

		Object.entries(untestable).forEach(([checkName, findings]) => {
			findings.forEach(untestableObject => {
				untestableDisplayHelper(untestableObject.checkName, untestableObject.endpoint, untestableObject.description);
			});
		});
	}

	// ---- Tool errors section ----
	const totalToolErrors = countTotalFindings(toolErrors);
	if (totalToolErrors > 0) {
		divider();
		console.log(chalk.magenta.bold(`  TOOL ERRORS  ${totalToolErrors}`));
		divider();
		console.log('');

		Object.entries(toolErrors).forEach(([checkName, findings]) => {
			findings.forEach(toolSpecificError => {
				toolErrorDisplayHelper(checkName, toolSpecificError.description);
			});
		});
	}
}

export function writeJsonReport(bySeverity, untestable, toolErrors, baseUrl) {
	const osPath = url.fileURLToPath(import.meta.url);
	const dir = path.dirname(osPath);
	const reportsDirectory = path.join(dir, '..', 'reports');

	const sanitizedUrl = baseUrl
		.replace(/^https?:\/\//, "")
		.replace(/[:/]/g, "_");

	const timestamp = new Date()
		.toISOString()
		.replace(/\.\d{3}Z$/, "")
		.replace("T", "_")
		.replace(/:/g, "-");

	const reportFilename = `${sanitizedUrl}_${timestamp}.json`;
	const fullPath = path.join(reportsDirectory, reportFilename);

	const flatArrayOfFindings = [
		...bySeverity.Critical, ...bySeverity.High, ...bySeverity.Medium, ...bySeverity.Low,
		...Object.values(untestable).flat(),
		...Object.values(toolErrors).flat()
	];

	const reportObject = {
		meta: {
			target: baseUrl,
			scannedAt: new Date().toISOString(),
			totalFindings: flatArrayOfFindings.length,
			summary: {
				Critical: bySeverity.Critical.length,
				High: bySeverity.High.length,
				Medium: bySeverity.Medium.length,
				Low: bySeverity.Low.length,
				Untestable: countTotalFindings(untestable),
				ToolErrors: countTotalFindings(toolErrors)
			}
		}, findings: flatArrayOfFindings
	};

	try {
		fs.mkdirSync(reportsDirectory, { recursive: true });
		fs.writeFileSync(fullPath, JSON.stringify(reportObject, null, 2));

		// const fullPath = reportsDirectory;
		// fs.writeFileSync(fullPath, "test");

		divider();
		console.log(chalk.dim(`  Full report saved to: ${fullPath}`));
		divider();

		return { success: true, path: fullPath };
	} catch (error) {
		divider();
		console.log(chalk.magenta.bold(`⚠️  [`) + chalk.cyan.bold('Report Writer') + chalk.magenta.bold(`]`));
		printWrappedField('Description', `Could not write report to disk: ${error.message}`);
		divider();

		return { success: false, path: null, reason: error.message };
	}
}