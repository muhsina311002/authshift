/**
 * AuthShift Type Definitions
 * Enterprise-grade types for the GitHub App security scanner
 */

// ============================================================================
// Environment & Configuration Types
// ============================================================================

/**
 * Cloudflare Worker environment bindings
 */
export interface Env {
	/** GitHub Webhook Secret for HMAC verification */
	GITHUB_WEBHOOK_SECRET: string;
	/** GitHub App ID for authentication */
	GITHUB_APP_ID: string;
	/** GitHub App Private Key (PEM format) */
	GITHUB_PRIVATE_KEY: string;
}

// ============================================================================
// GitHub Webhook Types
// ============================================================================

/**
 * GitHub webhook payload for pull_request events
 */
export interface PullRequestWebhook {
	action: 'opened' | 'synchronize' | 'reopened' | 'closed' | 'edited';
	number: number;
	pull_request: PullRequest;
	repository: Repository;
	installation?: Installation;
}

/**
 * Pull request details
 */
export interface PullRequest {
	id: number;
	number: number;
	title: string;
	body: string | null;
	state: 'open' | 'closed';
	url: string;
	html_url: string;
	diff_url: string;
	patch_url: string;
	base: {
		ref: string;
		sha: string;
		repo: Repository;
	};
	head: {
		ref: string;
		sha: string;
		repo: Repository;
	};
	user: GitHubUser;
	created_at: string;
	updated_at: string;
}

/**
 * Repository details
 */
export interface Repository {
	id: number;
	name: string;
	full_name: string;
	owner: GitHubUser;
	private: boolean;
	html_url: string;
	clone_url: string;
	default_branch: string;
}

/**
 * GitHub user/app details
 */
export interface GitHubUser {
	id: number;
	login: string;
	avatar_url: string;
	type: 'User' | 'Bot' | 'Organization';
}

/**
 * GitHub App installation details
 */
export interface Installation {
	id: number;
	node_id: string;
}

// ============================================================================
// Security Analysis Types
// ============================================================================

/**
 * Represents a single security finding from AST analysis
 */
export interface SecurityFinding {
	/** Unique identifier for the finding */
	id: string;
	/** Severity level of the vulnerability */
	severity: 'critical' | 'high' | 'medium' | 'low';
	/** Category of security issue */
	category: 'missing-auth' | 'weak-auth' | 'insecure-config';
	/** Human-readable description of the issue */
	message: string;
	/** File path where the issue was found */
	filePath: string;
	/** Line number in the file (1-indexed) */
	lineNumber: number;
	/** Column number in the file (0-indexed) */
	column: number;
	/** Code snippet containing the issue */
	snippet: string;
	/** Suggested remediation */
	suggestion: string;
}

/**
 * Result of analyzing a single file
 */
export interface FileAnalysisResult {
	/** Path to the analyzed file */
	filePath: string;
	/** Whether the file was successfully parsed */
	parsed: boolean;
	/** Parse error if any */
	parseError?: string;
	/** Security findings in this file */
	findings: SecurityFinding[];
}

/**
 * Complete analysis result for a pull request
 */
export interface AnalysisReport {
	/** PR identifier */
	prNumber: number;
	/** Repository full name (owner/repo) */
	repository: string;
	/** Timestamp of analysis */
	timestamp: string;
	/** Total files analyzed */
	filesAnalyzed: number;
	/** Total findings across all files */
	totalFindings: number;
	/** Grouped findings by severity */
	findingsBySeverity: {
		critical: number;
		high: number;
		medium: number;
		low: number;
	};
	/** Detailed findings */
	findings: SecurityFinding[];
}

// ============================================================================
// GitHub API Types
// ============================================================================

/**
 * Options for posting a review comment
 */
export interface ReviewCommentOptions {
	/** Repository owner */
	owner: string;
	/** Repository name */
	repo: string;
	/** PR number */
	pullNumber: number;
	/** Commit SHA to attach comment to */
	commitSha: string;
	/** Path to the file */
	path: string;
	/** Line number in the file */
	line: number;
	/** Comment body (markdown supported) */
	body: string;
	/** GitHub App installation ID */
	installationId?: number;
}

/**
 * Represents a diff entry from the PR diff API
 */
export interface DiffEntry {
	/** File path */
	path: string;
	/** Status: added, modified, removed, renamed */
	status: 'added' | 'modified' | 'removed' | 'renamed';
	/** Number of additions */
	additions: number;
	/** Number of deletions */
	deletions: number;
	/** Patch/diff content */
	patch?: string;
	/** Previous file path (for renames) */
	previousPath?: string;
}

// ============================================================================
// AST Analysis Types
// ============================================================================

/**
 * Configuration for the AST security analyzer
 */
export interface AnalyzerConfig {
	/** File extensions to analyze */
	extensions: string[];
	/** Auth middleware patterns to look for */
	authPatterns: AuthPattern[];
	/** Route patterns to analyze */
	routePatterns: RoutePattern[];
}

/**
 * Pattern that defines an authentication/authorization middleware
 */
export interface AuthPattern {
	/** Pattern name for identification */
	name: string;
	/** Import paths that indicate auth (e.g., 'middleware/auth') */
	importPaths: string[];
	/** Function names that indicate auth (e.g., 'requireAuth', 'protect') */
	functionNames: string[];
	/** Decorator names for frameworks like NestJS */
	decorators?: string[];
}

/**
 * Pattern that defines a route definition
 */
export interface RoutePattern {
	/** HTTP method (get, post, put, delete, etc.) */
	methods: string[];
	/** Frameworks to detect (express, fastify, nestjs, etc.) */
	frameworks: FrameworkPattern[];
}

/**
 * Framework-specific route patterns
 */
export interface FrameworkPattern {
	/** Framework name */
	name: string;
	/** Import paths that indicate this framework */
	importPaths: string[];
	/** Method names that define routes (e.g., 'get', 'post') */
	methodNames: string[];
	/** Router object names (e.g., 'router', 'app') */
	routerNames: string[];
}

// ============================================================================
// Webhook Processing Types
// ============================================================================

/**
 * Result of webhook verification
 */
export interface WebhookVerificationResult {
	/** Whether verification succeeded */
	valid: boolean;
	/** Error message if invalid */
	error?: string;
	/** Parsed payload if valid */
	payload?: PullRequestWebhook;
}

/**
 * Context passed through the processing pipeline
 */
export interface ProcessingContext {
	/** Webhook payload */
	payload: PullRequestWebhook;
	/** Repository owner */
	owner: string;
	/** Repository name */
	repo: string;
	/** PR number */
	prNumber: number;
}

/**
 * Result of the security scan operation
 */
export interface ScanResult {
	/** Whether the scan completed successfully */
	success: boolean;
	/** Error if scan failed */
	error?: string;
	/** Analysis report if successful */
	report?: AnalysisReport;
	/** Whether comments were posted */
	commentsPosted: boolean;
}
