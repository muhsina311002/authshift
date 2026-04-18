declare module 'cloudflare:test' {
	interface ProvidedEnv extends Env {
		GITHUB_WEBHOOK_SECRET: string;
		GITHUB_APP_ID: string;
		GITHUB_PRIVATE_KEY: string;
	}
}
