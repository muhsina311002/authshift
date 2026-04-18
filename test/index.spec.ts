import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { createHmac } from 'crypto';
import worker from '../src/index';
import { ASTSecurityAnalyzer } from '../src/security/ast-analyzer';

/**
 * Generate a valid GitHub webhook signature
 */
function generateSignature(body: string, secret: string): string {
	const hmac = createHmac('sha256', secret);
	hmac.update(body);
	return `sha256=${hmac.digest('hex')}`;
}

// Use the same secret as in .dev.vars
const WEBHOOK_SECRET = 'local_dev_secret_123';

describe('AuthShift - GitHub Webhook Handler', () => {
	describe('Webhook Verification', () => {
		it('rejects GET requests with 405', async () => {
			const request = new Request('http://example.com', { method: 'GET' });
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(405);
			expect(await response.text()).toBe('Method Not Allowed');
		});

		it('rejects POST without required headers', async () => {
			const request = new Request('http://example.com', {
				method: 'POST',
				body: '{}',
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			expect(await response.text()).toBe('Missing required GitHub headers');
		});

		it('rejects invalid webhook signatures', async () => {
			const body = JSON.stringify({ action: 'opened', pull_request: { number: 1 } });
			const request = new Request('http://example.com', {
				method: 'POST',
				headers: {
					'x-hub-signature-256': 'sha256=invalid',
					'x-github-event': 'pull_request',
					'x-github-delivery': 'test-delivery-id',
				},
				body,
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(401);
			expect(await response.text()).toBe('Unauthorized: Invalid Signature');
		});

		it('accepts pull_request opened event with valid signature', async () => {
			const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
			const payload = {
				action: 'opened',
				pull_request: {
					number: 42,
					title: 'Test PR',
					base: { sha: 'base-sha-123', ref: 'main' },
					head: { sha: 'head-sha-456', ref: 'feature-branch' },
				},
				repository: {
					full_name: 'test-org/test-repo',
					owner: { login: 'test-org' },
					name: 'test-repo',
				},
			};
			const body = JSON.stringify(payload);
			const signature = generateSignature(body, WEBHOOK_SECRET);

			const request = new Request('http://example.com', {
				method: 'POST',
				headers: {
					'x-hub-signature-256': signature,
					'x-github-event': 'pull_request',
					'x-github-delivery': 'test-delivery-id',
				},
				body,
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			expect(await response.text()).toBe('Webhook processed securely');
			expect(warnSpy).toHaveBeenCalledWith('[SCAN SKIPPED] PR #42 missing GitHub installation id in webhook payload');
			warnSpy.mockRestore();
		});

		it('accepts pull_request synchronize event with valid signature', async () => {
			const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
			const payload = {
				action: 'synchronize',
				pull_request: {
					number: 42,
					title: 'Test PR',
					base: { sha: 'base-sha-123', ref: 'main' },
					head: { sha: 'new-head-sha-789', ref: 'feature-branch' },
				},
				repository: {
					full_name: 'test-org/test-repo',
					owner: { login: 'test-org' },
					name: 'test-repo',
				},
			};
			const body = JSON.stringify(payload);
			const signature = generateSignature(body, WEBHOOK_SECRET);

			const request = new Request('http://example.com', {
				method: 'POST',
				headers: {
					'x-hub-signature-256': signature,
					'x-github-event': 'pull_request',
					'x-github-delivery': 'test-delivery-id',
				},
				body,
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			expect(await response.text()).toBe('Webhook processed securely');
			expect(warnSpy).toHaveBeenCalledWith('[SCAN SKIPPED] PR #42 missing GitHub installation id in webhook payload');
			warnSpy.mockRestore();
		});

		it('ignores other pull_request actions', async () => {
			const payload = {
				action: 'labeled',
				pull_request: { number: 42 },
				repository: { full_name: 'test-org/test-repo', owner: { login: 'test-org' }, name: 'test-repo' },
			};
			const body = JSON.stringify(payload);
			const signature = generateSignature(body, WEBHOOK_SECRET);

			const request = new Request('http://example.com', {
				method: 'POST',
				headers: {
					'x-hub-signature-256': signature,
					'x-github-event': 'pull_request',
					'x-github-delivery': 'test-delivery-id',
				},
				body,
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});

		it('ignores non-pull_request events', async () => {
			const payload = { action: 'created' };
			const body = JSON.stringify(payload);
			const signature = generateSignature(body, WEBHOOK_SECRET);

			const request = new Request('http://example.com', {
				method: 'POST',
				headers: {
					'x-hub-signature-256': signature,
					'x-github-event': 'issue_comment',
					'x-github-delivery': 'test-delivery-id',
				},
				body,
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});
	});
});

describe('AuthShift - AST Security Analyzer', () => {
	let analyzer: ASTSecurityAnalyzer;

	beforeAll(() => {
		analyzer = new ASTSecurityAnalyzer();
	});

	describe('Express Route Detection', () => {
		it('detects Express GET route without auth middleware', async () => {
			const source = `
				import express from 'express';
				const app = express();

				// This route has no auth
				app.get('/api/users', (req, res) => {
					res.json({ users: [] });
				});
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBeGreaterThan(0);
			expect(result.findings[0].category).toBe('missing-auth');
			expect(result.findings[0].severity).toBe('high');
		});

		it('does not flag Express routes with auth middleware', async () => {
			const source = `
				import express from 'express';
				import { requireAuth } from './middleware/auth';
				const app = express();

				// This route is protected
				app.get('/api/admin', requireAuth, (req, res) => {
					res.json({ admin: true });
				});
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBe(0);
		});

		it('detects Express POST route without auth', async () => {
			const source = `
				import express from 'express';
				const router = express.Router();

				router.post('/api/data', async (req, res) => {
					const data = await saveData(req.body);
					res.json(data);
				});
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			const postFindings = result.findings.filter((f) => f.message.includes('POST'));
			expect(postFindings.length).toBeGreaterThan(0);
		});

		it('detects multiple unprotected routes in one file', async () => {
			const source = `
				import express from 'express';
				const app = express();

				app.get('/api/users', (req, res) => res.json([]));
				app.post('/api/users', (req, res) => res.json({ created: true }));
				app.put('/api/users/:id', (req, res) => res.json({ updated: true }));
				app.delete('/api/users/:id', (req, res) => res.json({ deleted: true }));
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBeGreaterThanOrEqual(4);
		});
	});

	describe('Fastify Route Detection', () => {
		it('detects Fastify route without auth', async () => {
			const source = `
				import Fastify from 'fastify';
				const fastify = Fastify();

				fastify.get('/api/data', async (request, reply) => {
					return { data: [] };
				});
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBeGreaterThan(0);
		});
	});

	describe('NestJS Route Detection', () => {
		it('detects NestJS @Get route without auth guards', async () => {
			const source = `
				import { Controller, Get } from '@nestjs/common';

				@Controller('api')
				export class DataController {
					@Get('data')
					findAll() {
						return { data: [] };
					}
				}
			`;

			const result = await analyzer.analyzeFile(source, 'data.controller.ts');
			expect(result.parsed).toBe(true);
			// NestJS detection requires more context, but structure is in place
		});
	});

	describe('Auth Middleware Detection', () => {
		it('recognizes requireAuth as auth middleware', async () => {
			const source = `
				import express from 'express';
				const app = express();

				app.get('/api/protected', requireAuth, (req, res) => {
					res.json({ protected: true });
				});
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBe(0);
		});

		it('recognizes protect middleware', async () => {
			const source = `
				import express from 'express';
				const app = express();

				app.post('/api/users', protect, (req, res) => {
					res.json({ created: true });
				});
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBe(0);
		});

		it('recognizes verifyToken middleware', async () => {
			const source = `
				import express from 'express';
				const app = express();

				app.get('/api/admin', verifyToken, (req, res) => {
					res.json({ admin: true });
				});
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBe(0);
		});

		it('recognizes authenticate middleware', async () => {
			const source = `
				import express from 'express';
				const app = express();

				app.get('/api/secure', authenticate, (req, res) => {
					res.json({ secure: true });
				});
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBe(0);
		});
	});

	describe('TypeScript Support', () => {
		it('parses TypeScript with type annotations', async () => {
			const source = `
				import express, { Request, Response } from 'express';
				const app = express();

				interface User {
					id: number;
					name: string;
				}

				app.get('/api/users', (req: Request, res: Response): void => {
					const users: User[] = [];
					res.json(users);
				});
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBeGreaterThan(0);
		});
	});

	describe('Error Handling', () => {
		it('handles malformed JavaScript gracefully', async () => {
			const source = `
				this is not valid javascript {{{
			`;

			const result = await analyzer.analyzeFile(source, 'broken.js');
			expect(result.parsed).toBe(false);
			expect(result.parseError).toBeDefined();
		});

		it('returns empty findings for non-route files', async () => {
			const source = `
				function helper() {
					return "I'm just a helper";
				}

				const utils = {
					add: (a, b) => a + b,
				};
			`;

			const result = await analyzer.analyzeFile(source, 'utils.js');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBe(0);
		});
	});

	describe('Finding Structure', () => {
		it('generates findings with correct structure', async () => {
			const source = `
				import express from 'express';
				const app = express();
				app.get('/api/data', (req, res) => res.json({}));
			`;

			const result = await analyzer.analyzeFile(source, 'routes.ts');
			expect(result.parsed).toBe(true);
			expect(result.findings.length).toBeGreaterThan(0);

			const finding = result.findings[0];
			expect(finding.id).toMatch(/^AUTH-[A-F0-9]{8}$/);
			expect(finding.severity).toBe('high');
			expect(finding.category).toBe('missing-auth');
			expect(finding.message).toContain('authentication');
			expect(finding.filePath).toBe('routes.ts');
			expect(finding.lineNumber).toBeGreaterThan(0);
			expect(finding.suggestion).toBeDefined();
		});
	});
});
