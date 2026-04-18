import { Webhooks } from '@octokit/webhooks';
import { GitHubService } from './github/service';
import { ASTSecurityAnalyzer } from './security/ast-analyzer';
import { SecurityScanner } from './security/scanner';
import type { Env, PullRequestWebhook } from './types';

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// 1. Reject anything that isn't a POST request
		if (request.method !== 'POST') {
			return new Response('Method Not Allowed', { status: 405 });
		}

		// 2. Extract GitHub's required security headers
		const signature = request.headers.get('x-hub-signature-256');
		const eventName = request.headers.get('x-github-event');
		const deliveryId = request.headers.get('x-github-delivery');

		if (!signature || !eventName || !deliveryId) {
			return new Response('Missing required GitHub headers', { status: 400 });
		}

		try {
			// 3. Read the raw body as text for cryptographic verification
			const body = await request.text();

			const webhooks = new Webhooks({
				secret: env.GITHUB_WEBHOOK_SECRET,
			});

			// 4. Mathematically verify the payload signature
			let isValid = false;
			try {
				isValid = await webhooks.verify(body, signature);
			} catch {
				// Signature verification failed (e.g., malformed signature)
				return new Response('Unauthorized: Invalid Signature', { status: 401 });
			}

			if (!isValid) {
				return new Response('Unauthorized: Invalid Signature', { status: 401 });
			}

			// 5. Parse the verified payload
			const payload = JSON.parse(body) as PullRequestWebhook;

			// 6. Route the specific events we care about
			if (eventName === 'pull_request') {
				const action = payload.action;

				// We only want to scan when code is initially opened or updated
				if (action === 'opened' || action === 'synchronize') {
					console.log(`[SCAN TRIGGERED] PR #${payload.pull_request.number} on ${payload.repository.full_name}`);

					// Offload heavy scanning to background to prevent GitHub timeout
					ctx.waitUntil(processSecurityScan(payload, env));
				}
			}

			// Always return a 200 quickly so GitHub doesn't timeout the webhook
			return new Response('Webhook processed securely', { status: 200 });
		} catch (error) {
			console.error('Fatal Webhook Error:', error);
			return new Response('Internal Server Error', { status: 500 });
		}
	},
};

/**
 * Process the security scan asynchronously
 * This runs in the background after the HTTP response is sent
 */
async function processSecurityScan(payload: PullRequestWebhook, env: Env): Promise<void> {
	const startTime = Date.now();
	const owner = payload.repository.owner.login;
	const repo = payload.repository.name;
	const prNumber = payload.pull_request.number;
	const installationId = payload.installation?.id;

	if (!installationId) {
		console.warn(`[SCAN SKIPPED] PR #${prNumber} missing GitHub installation id in webhook payload`);
		return;
	}

	try {
		// Initialize services
		const githubService = new GitHubService(env);
		const analyzer = new ASTSecurityAnalyzer();
		const scanner = new SecurityScanner(githubService, analyzer);

		// Execute the security scan pipeline
		const result = await scanner.scanPullRequest({
			owner,
			repo,
			prNumber,
			baseSha: payload.pull_request.base.sha,
			headSha: payload.pull_request.head.sha,
			installationId,
		});

		const duration = Date.now() - startTime;

		if (result.success) {
			console.log(`[SCAN COMPLETED] PR #${prNumber} analyzed in ${duration}ms. Found ${result.report?.totalFindings || 0} issues.`);
		} else {
			console.error(`[SCAN FAILED] PR #${prNumber}: ${result.error}`);
		}
	} catch (error) {
		console.error(`[UNEXPECTED ERROR] PR #${prNumber}:`, error);
	}
}

// Re-export types for consumers
export * from './types';
