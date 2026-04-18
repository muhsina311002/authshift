# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Authshift is a Cloudflare Worker that receives GitHub webhook events, verifies their signatures, and triggers code scanning on pull request events (opened/synchronize).

## Architecture

- **Entry Point**: `src/index.ts` - Single worker export with a `fetch` handler
- **Environment**: Cloudflare Workers runtime with `nodejs_compat` flag
- **Webhook Verification**: Uses `@octokit/webhooks` for cryptographic signature verification
- **Event Handling**: Currently handles `pull_request` events for `opened` and `synchronize` actions

## Environment Variables

Required secrets (set via `wrangler secret put`):

- `GITHUB_WEBHOOK_SECRET` - GitHub webhook secret for HMAC signature verification

Local development uses `.dev.vars` file (gitignored).

## Build & Development Commands

```bash
# Install dependencies
pnpm install

# Start local dev server
pnpm run dev
# or
wrangler dev

# Run tests
pnpm test
# or
vitest

# Deploy to production
pnpm run deploy
# or
wrangler deploy

# Generate Cloudflare types (after config changes)
pnpm run cf-typegen
```

## Testing

Tests use Vitest with `@cloudflare/vitest-pool-workers` for Workers runtime simulation:

```bash
# Run all tests
vitest

# Run in watch mode
vitest --watch
```

Test files are in `test/` directory. The test environment provides:

- `env` - Access to bindings
- `SELF.fetch()` - Integration-style requests to the worker
- `createExecutionContext()` / `waitOnExecutionContext()` - Unit-style testing

## Request Flow

1. Rejects non-POST requests with 405
2. Extracts required headers: `x-hub-signature-256`, `x-github-event`, `x-github-delivery`
3. Verifies webhook signature using `@octokit/webhooks`
4. Parses JSON payload
5. Routes `pull_request` events (action: `opened` or `synchronize`)
6. Returns 200 quickly to prevent GitHub webhook timeouts

## Key Dependencies

- `@octokit/webhooks` - GitHub webhook signature verification
- `@cloudflare/vitest-pool-workers` - Workers runtime testing
- `wrangler` - CLI for deployment and local dev

## Notes

- The worker must respond quickly (GitHub has a 10-second webhook timeout)
- Long-running scan operations should be offloaded to background tasks (queue bindings, Durable Objects, etc.)
- Source maps are uploaded for observability in Cloudflare dashboard
