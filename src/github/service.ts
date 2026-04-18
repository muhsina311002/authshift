import { App } from '@octokit/app';
import type { Env, DiffEntry, ReviewCommentOptions } from '../types';

type InstallationOctokit = Awaited<ReturnType<App['getInstallationOctokit']>>;

/**
 * GitHub Service - Handles all GitHub API interactions
 * Includes authentication, diff fetching, and review comment posting
 */
export class GitHubService {
	private app: App;

	constructor(env: Env) {
		// Validate required environment variables
		if (!env.GITHUB_APP_ID) {
			throw new Error('GITHUB_APP_ID environment variable is required');
		}
		if (!env.GITHUB_PRIVATE_KEY) {
			throw new Error('GITHUB_PRIVATE_KEY environment variable is required');
		}

		this.app = new App({
			appId: env.GITHUB_APP_ID,
			privateKey: this.normalizePrivateKey(env.GITHUB_PRIVATE_KEY),
		});
	}

	/**
	 * Normalize private key value from environment variables.
	 * Many platforms store multiline secrets with escaped newlines.
	 */
	private normalizePrivateKey(privateKey: string): string {
		return privateKey.replace(/\\n/g, '\n').trim();
	}

	/**
	 * Get an authenticated Octokit client for a specific installation
	 */
	private async getInstallationClient(owner: string, repo: string, installationId?: number): Promise<InstallationOctokit> {
		try {
			if (installationId) {
				return await this.app.getInstallationOctokit(installationId);
			}

			// Get the installation ID for this repository
			const { data: installation } = await this.app.octokit.request('GET /repos/{owner}/{repo}/installation', {
				owner,
				repo,
			});

			return await this.app.getInstallationOctokit(installation.id);
		} catch (error) {
			console.error('Failed to get installation client:', error);
			throw new Error(`GitHub App authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`, {
				cause: error,
			});
		}
	}

	/**
	 * Fetch the list of files changed in a pull request
	 */
	async fetchPullRequestFiles(owner: string, repo: string, prNumber: number, installationId?: number): Promise<DiffEntry[]> {
		const octokit = await this.getInstallationClient(owner, repo, installationId);

		try {
			const { data: files } = await octokit.request('GET /repos/{owner}/{repo}/pulls/{pull_number}/files', {
				owner,
				repo,
				pull_number: prNumber,
				per_page: 100,
			});

			return files.map(
				(file: { filename: string; status: string; additions: number; deletions: number; patch?: string; previous_filename?: string }) => ({
					path: file.filename,
					status: file.status as 'added' | 'modified' | 'removed' | 'renamed',
					additions: file.additions,
					deletions: file.deletions,
					patch: file.patch,
					previousPath: file.previous_filename,
				}),
			);
		} catch (error) {
			console.error('Failed to fetch PR files:', error);
			throw error;
		}
	}

	/**
	 * Fetch the raw content of a file at a specific commit
	 */
	async fetchFileContent(owner: string, repo: string, path: string, ref: string, installationId?: number): Promise<string | null> {
		const octokit = await this.getInstallationClient(owner, repo, installationId);

		try {
			const { data } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
				owner,
				repo,
				path,
				ref,
			});

			// Handle file content
			if ('content' in data && 'encoding' in data) {
				// Decode base64 content
				const content = data.content;
				const encoding = data.encoding as string;

				if (encoding === 'base64') {
					// Cloudflare Workers don't have Buffer, use atob
					return atob(content.replace(/\s/g, ''));
				}
				return content;
			}

			return null;
		} catch (error) {
			// File might not exist at this ref
			if (typeof error === 'object' && error !== null && 'status' in error && typeof error.status === 'number' && error.status === 404) {
				return null;
			}
			console.error(`Failed to fetch file content ${path}@${ref}:`, error);
			throw error;
		}
	}

	/**
	 * Fetch the diff (patch) for a specific file in a PR
	 */
	async fetchFileDiff(owner: string, repo: string, prNumber: number, path: string, installationId?: number): Promise<string | null> {
		const octokit = await this.getInstallationClient(owner, repo, installationId);

		try {
			const { data: files } = await octokit.request('GET /repos/{owner}/{repo}/pulls/{pull_number}/files', {
				owner,
				repo,
				pull_number: prNumber,
			});

			const file = files.find((f: { filename: string; patch?: string }) => f.filename === path);
			return file?.patch || null;
		} catch (error) {
			console.error('Failed to fetch file diff:', error);
			throw error;
		}
	}

	/**
	 * Post a review comment on a specific line of a PR
	 */
	async postReviewComment(options: ReviewCommentOptions): Promise<void> {
		const { owner, repo, pullNumber, commitSha, path, line, body, installationId } = options;
		const octokit = await this.getInstallationClient(owner, repo, installationId);

		try {
			// Post the review comment
			await octokit.request('POST /repos/{owner}/{repo}/pulls/{pull_number}/comments', {
				owner,
				repo,
				pull_number: pullNumber,
				commit_id: commitSha,
				path,
				line,
				body,
			});

			console.log(`Posted review comment on ${path}:${line}`);
		} catch (error) {
			console.error('Failed to post review comment:', error);
			throw error;
		}
	}

	/**
	 * Post a general PR comment (not tied to a specific line)
	 */
	async postPRComment(owner: string, repo: string, prNumber: number, body: string, installationId?: number): Promise<void> {
		const octokit = await this.getInstallationClient(owner, repo, installationId);

		try {
			await octokit.request('POST /repos/{owner}/{repo}/issues/{issue_number}/comments', {
				owner,
				repo,
				issue_number: prNumber,
				body,
			});

			console.log(`Posted PR comment on #${prNumber}`);
		} catch (error) {
			console.error('Failed to post PR comment:', error);
			throw error;
		}
	}

	/**
	 * Create a review with multiple comments
	 */
	async createReview(
		owner: string,
		repo: string,
		prNumber: number,
		comments: Array<{ path: string; line: number; body: string }>,
		summary: string,
		installationId?: number,
	): Promise<void> {
		const octokit = await this.getInstallationClient(owner, repo, installationId);

		try {
			// Get the PR details for the head SHA
			const { data: pr } = await octokit.request('GET /repos/{owner}/{repo}/pulls/{pull_number}', {
				owner,
				repo,
				pull_number: prNumber,
			});

			// Post comments in batches if there are many
			const BATCH_SIZE = 10;
			for (let i = 0; i < comments.length; i += BATCH_SIZE) {
				const batch = comments.slice(i, i + BATCH_SIZE);
				const reviewComments = batch.map((comment) => ({
					path: comment.path,
					line: comment.line,
					body: comment.body,
				}));

				// Submit the review
				await octokit.request('POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews', {
					owner,
					repo,
					pull_number: prNumber,
					commit_id: pr.head.sha,
					event: comments.length > 0 ? 'COMMENT' : 'APPROVE',
					body: i === 0 ? summary : undefined,
					comments: reviewComments,
				});
			}

			console.log(`Created review on PR #${prNumber} with ${comments.length} comments`);
		} catch (error) {
			console.error('Failed to create review:', error);
			throw error;
		}
	}
}
