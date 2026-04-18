import type { GitHubService } from '../github/service';
import type { ASTSecurityAnalyzer } from './ast-analyzer';
import type { SecurityFinding, FileAnalysisResult, AnalysisReport, ScanResult, DiffEntry } from '../types';

/**
 * Security Scanner - Orchestrates the PR security analysis pipeline
 */
export class SecurityScanner {
	private githubService: GitHubService;
	private analyzer: ASTSecurityAnalyzer;

	constructor(githubService: GitHubService, analyzer: ASTSecurityAnalyzer) {
		this.githubService = githubService;
		this.analyzer = analyzer;
	}

	/**
	 * Scan a pull request for security issues
	 */
	async scanPullRequest(options: {
		owner: string;
		repo: string;
		prNumber: number;
		baseSha: string;
		headSha: string;
		installationId?: number;
	}): Promise<ScanResult> {
		const { owner, repo, prNumber, headSha, installationId } = options;

		try {
			// 1. Fetch the list of changed files
			const files = await this.githubService.fetchPullRequestFiles(owner, repo, prNumber, installationId);

			// 2. Filter for source code files we can analyze
			const analyzableFiles = this.filterAnalyzableFiles(files);

			// 3. Analyze each file
			const results: FileAnalysisResult[] = [];

			for (const file of analyzableFiles) {
				// Skip deleted files
				if (file.status === 'removed') continue;

				// Fetch the file content at the head SHA
				const content = await this.githubService.fetchFileContent(owner, repo, file.path, headSha, installationId);

				if (!content) {
					console.warn(`Could not fetch content for ${file.path}`);
					continue;
				}

				// Analyze the file (now async)
				const result = await this.analyzer.analyzeFile(content, file.path);
				results.push(result);

				console.log(`Analyzed ${file.path}: ${result.parsed ? result.findings.length + ' findings' : 'parse error'}`);
			}

			// 4. Aggregate findings
			const allFindings = results.flatMap((r) => r.findings);

			// 5. Create analysis report
			const report = this.createReport(prNumber, `${owner}/${repo}`, results, allFindings);

			// 6. Post review comments for findings
			let commentsPosted = false;
			if (allFindings.length > 0) {
				await this.postFindings(owner, repo, prNumber, allFindings, installationId);
				commentsPosted = true;
			}

			return {
				success: true,
				report,
				commentsPosted,
			};
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			console.error('Scan failed:', error);

			// Try to post an error comment
			try {
				await this.githubService.postPRComment(
					owner,
					repo,
					prNumber,
					`## AuthShift Security Scan Error\n\nUnable to complete security analysis: ${errorMessage}`,
					installationId,
				);
			} catch {
				// Ignore errors from error reporting
			}

			return {
				success: false,
				error: errorMessage,
				commentsPosted: false,
			};
		}
	}

	/**
	 * Filter for files that we can analyze
	 */
	private filterAnalyzableFiles(files: DiffEntry[]): DiffEntry[] {
		const analyzableExtensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];

		return files.filter((file) => {
			// Skip deleted files
			if (file.status === 'removed') return false;

			// Check extension
			const hasValidExt = analyzableExtensions.some((ext) => file.path.endsWith(ext));

			// Skip test files, node_modules, etc.
			const shouldSkip =
				file.path.includes('node_modules/') ||
				file.path.includes('dist/') ||
				file.path.includes('build/') ||
				file.path.includes('.test.') ||
				file.path.includes('.spec.') ||
				file.path.includes('__tests__/') ||
				file.path.includes('__mocks__/');

			return hasValidExt && !shouldSkip;
		});
	}

	/**
	 * Create the analysis report
	 */
	private createReport(prNumber: number, repository: string, results: FileAnalysisResult[], findings: SecurityFinding[]): AnalysisReport {
		return {
			prNumber,
			repository,
			timestamp: new Date().toISOString(),
			filesAnalyzed: results.length,
			totalFindings: findings.length,
			findingsBySeverity: {
				critical: findings.filter((f) => f.severity === 'critical').length,
				high: findings.filter((f) => f.severity === 'high').length,
				medium: findings.filter((f) => f.severity === 'medium').length,
				low: findings.filter((f) => f.severity === 'low').length,
			},
			findings,
		};
	}

	/**
	 * Post findings as PR review comments
	 */
	private async postFindings(
		owner: string,
		repo: string,
		prNumber: number,
		findings: SecurityFinding[],
		installationId?: number,
	): Promise<void> {
		// Format findings as review comments
		const comments = findings.map((finding) => ({
			path: finding.filePath,
			line: finding.lineNumber,
			body: this.formatFindingComment(finding),
		}));

		// Create a summary
		const summary = this.formatSummary(findings);

		// Post the review
		await this.githubService.createReview(owner, repo, prNumber, comments, summary, installationId);
	}

	/**
	 * Format a single finding as a comment
	 */
	private formatFindingComment(finding: SecurityFinding): string {
		const severityEmoji = {
			critical: '🚨',
			high: '⚠️',
			medium: '⚡',
			low: 'ℹ️',
		}[finding.severity];

		return `## ${severityEmoji} AuthShift Security Finding: ${finding.id}

**Severity:** ${finding.severity.toUpperCase()}
**Category:** ${finding.category}

**Issue:** ${finding.message}

**Suggestion:** ${finding.suggestion}

---
*AuthShift - Automated Security Analysis*`;
	}

	/**
	 * Format the summary comment
	 */
	private formatSummary(findings: SecurityFinding[]): string {
		const bySeverity = {
			critical: findings.filter((f) => f.severity === 'critical').length,
			high: findings.filter((f) => f.severity === 'high').length,
			medium: findings.filter((f) => f.severity === 'medium').length,
			low: findings.filter((f) => f.severity === 'low').length,
		};

		let summary = '## 🔒 AuthShift Security Analysis\n\n';

		if (findings.length === 0) {
			summary += '✅ No security issues detected in this PR.\n';
		} else {
			summary += `Found **${findings.length}** potential security issue(s):\n\n`;
			summary += '| Severity | Count |\n';
			summary += '|----------|-------|\n';
			summary += `| 🚨 Critical | ${bySeverity.critical} |\n`;
			summary += `| ⚠️ High | ${bySeverity.high} |\n`;
			summary += `| ⚡ Medium | ${bySeverity.medium} |\n`;
			summary += `| ℹ️ Low | ${bySeverity.low} |\n\n`;
			summary += 'Please review the inline comments for specific issues and remediations.\n';
		}

		summary += '\n---\n*AuthShift - Zero-cost serverless security for your APIs*';

		return summary;
	}
}
