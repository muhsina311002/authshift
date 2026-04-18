import { parse } from '@babel/parser';
import type { File, Node, CallExpression, MemberExpression, Decorator, StringLiteral } from '@babel/types';
import type { SecurityFinding, FileAnalysisResult } from '../types';

/**
 * AST Security Analyzer - Detects missing authentication on API routes
 * Uses Babel parser for precise AST traversal
 */
export class ASTSecurityAnalyzer {
	/**
	 * Parse source code into an AST
	 */
	private parseSource(source: string, filename: string): File | null {
		try {
			return parse(source, {
				sourceType: 'module',
				allowImportExportEverywhere: true,
				allowReturnOutsideFunction: true,
				plugins: [
					'jsx',
					'typescript',
					'decorators-legacy',
					'classProperties',
					'objectRestSpread',
					'asyncGenerators',
					'dynamicImport',
					'optionalChaining',
					'nullishCoalescingOperator',
				],
			});
		} catch (error) {
			console.error(`Failed to parse ${filename}:`, error);
			return null;
		}
	}

	/**
	 * Analyze a source file for security issues
	 */
	async analyzeFile(source: string, filePath: string): Promise<FileAnalysisResult> {
		const ast = this.parseSource(source, filePath);

		if (!ast) {
			return {
				filePath,
				parsed: false,
				parseError: 'Failed to parse source code',
				findings: [],
			};
		}

		const findings: SecurityFinding[] = [];
		const imports = this.extractImportsAndInstances(ast);

		// Walk the AST looking for route definitions
		this.walkAST(ast, filePath, imports, findings);

		return {
			filePath,
			parsed: true,
			findings,
		};
	}

	/**
	 * Extract imports and track framework instances (e.g., app = express())
	 */
	private extractImportsAndInstances(ast: File): Map<string, string> {
		const imports = new Map<string, string>();

		// First pass: collect imports
		this.visitNode(ast, (node) => {
			// ES6 imports: import express from 'express'
			if (node.type === 'ImportDeclaration') {
				const source = node.source.value;
				for (const spec of node.specifiers) {
					if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportSpecifier') {
						imports.set(spec.local.name, source);
					}
				}
			}

			// require() patterns: const express = require('express')
			if (node.type === 'VariableDeclarator' && node.init?.type === 'CallExpression') {
				const init = node.init;
				if (
					init.callee.type === 'Identifier' &&
					init.callee.name === 'require' &&
					init.arguments.length > 0 &&
					init.arguments[0].type === 'StringLiteral'
				) {
					const source = (init.arguments[0] as StringLiteral).value;
					if (node.id.type === 'Identifier') {
						imports.set(node.id.name, source);
					}
				}
			}
		});

		// Second pass: track framework instances
		// e.g., const app = express(), const router = express.Router(), const server = fastify()
		this.visitNode(ast, (node) => {
			if (node.type === 'VariableDeclarator' && node.init) {
				// Case: const app = express()
				if (node.init.type === 'CallExpression' && node.id.type === 'Identifier') {
					const callee = node.init.callee;
					if (callee.type === 'Identifier') {
						const calleeSource = imports.get(callee.name);
						if (calleeSource && (calleeSource.includes('express') || calleeSource.includes('fastify') || calleeSource.includes('hono'))) {
							imports.set(node.id.name, calleeSource);
						}
					}
					// Case: const router = express.Router()
					if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier') {
						const objectSource = imports.get(callee.object.name);
						if (objectSource && objectSource.includes('express')) {
							imports.set(node.id.name, objectSource);
						}
					}
				}

				// Case: const fastify = Fastify({ ... }) - Fastify is often used as Fastify()
				if (node.init.type === 'CallExpression' && node.id.type === 'Identifier') {
					const callee = node.init.callee;
					if (callee.type === 'Identifier') {
						const name = callee.name.toLowerCase();
						if (name === 'fastify') {
							imports.set(node.id.name, 'fastify');
						}
					}
				}
			}
		});

		return imports;
	}

	/**
	 * Walk the AST and find security issues
	 */
	private walkAST(node: Node, filePath: string, imports: Map<string, string>, findings: SecurityFinding[]): void {
		this.visitNode(node, (childNode) => {
			// Check for Express/Fastify/Hono route calls
			if (childNode.type === 'CallExpression') {
				this.analyzeRouteCall(childNode, filePath, imports, findings);
			}

			// Check for NestJS decorators
			if (childNode.type === 'Decorator') {
				this.analyzeNestDecorator(childNode, filePath, imports, findings);
			}
		});
	}

	/**
	 * Visit all nodes in the AST
	 */
	private visitNode(node: unknown, callback: (node: Node) => void): void {
		if (!node || typeof node !== 'object') {
			return;
		}

		if ('type' in node && typeof (node as Node).type === 'string') {
			const typedNode = node as Node;
			callback(typedNode);

			for (const key of Object.keys(typedNode)) {
				const value = (typedNode as unknown as Record<string, unknown>)[key];
				this.visitValue(value, callback);
			}
		}
	}

	/**
	 * Visit a value (handles arrays and objects)
	 */
	private visitValue(value: unknown, callback: (node: Node) => void): void {
		if (Array.isArray(value)) {
			for (const item of value) {
				this.visitValue(item, callback);
			}
		} else if (value && typeof value === 'object') {
			this.visitNode(value, callback);
		}
	}

	/**
	 * Analyze Express/Fastify style route calls
	 */
	private analyzeRouteCall(node: CallExpression, filePath: string, imports: Map<string, string>, findings: SecurityFinding[]): void {
		const callee = node.callee;

		// Check if this is a method call like app.get(), router.post(), etc.
		if (callee.type !== 'MemberExpression') return;

		const methodName = this.getPropertyName(callee);
		if (!methodName) return;

		// Check if this is an HTTP method call
		const httpMethods = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all'];
		if (!httpMethods.includes(methodName.toLowerCase())) return;

		// Get the object being called on (app, router, etc.)
		const objectName = this.getObjectName(callee);
		if (!objectName) return;

		// Check if this object is likely an Express/Fastify app/router
		const isExpressApp = this.isExpressRouter(objectName, imports);
		const isFastifyApp = this.isFastifyInstance(objectName, imports);
		const isHonoApp = this.isHonoApp(objectName, imports);

		if (!isExpressApp && !isFastifyApp && !isHonoApp) return;

		// This is a route definition - check for auth middleware
		const hasAuth = this.checkForAuthMiddleware(node);

		if (!hasAuth) {
			const loc = node.loc;
			findings.push({
				id: this.generateFindingId(filePath, loc?.start.line || 0),
				severity: 'high',
				category: 'missing-auth',
				message: `API route "${methodName.toUpperCase()}" lacks authentication middleware`,
				filePath,
				lineNumber: loc?.start.line || 0,
				column: loc?.start.column || 0,
				snippet: this.extractSnippet(),
				suggestion: 'Add authentication middleware such as requireAuth, protect, or verifyToken to secure this route',
			});
		}
	}

	/**
	 * Analyze NestJS decorators
	 */
	private analyzeNestDecorator(node: Decorator, filePath: string, imports: Map<string, string>, findings: SecurityFinding[]): void {
		if (!node.expression) return;

		let decoratorName: string | null = null;
		let decoratorArgs: string[] = [];

		if (node.expression.type === 'CallExpression') {
			const callee = node.expression.callee;
			if (callee.type === 'Identifier') {
				decoratorName = callee.name;
			}
			decoratorArgs = node.expression.arguments.filter((arg): arg is StringLiteral => arg.type === 'StringLiteral').map((arg) => arg.value);
		} else if (node.expression.type === 'Identifier') {
			decoratorName = node.expression.name;
		}

		if (!decoratorName) return;

		const routeDecorators = ['Get', 'Post', 'Put', 'Patch', 'Delete', 'Options', 'Head', 'All'];
		if (!routeDecorators.includes(decoratorName)) return;

		const isNestRoute = imports.get(decoratorName)?.includes('@nestjs/common') || this.hasNestJsImport(imports);

		if (!isNestRoute) return;

		const loc = node.loc;
		const routePath = decoratorArgs[0] || '/';
		findings.push({
			id: this.generateFindingId(filePath, loc?.start.line || 0),
			severity: 'high',
			category: 'missing-auth',
			message: `NestJS @${decoratorName}("${routePath}") route may lack authentication guards`,
			filePath,
			lineNumber: loc?.start.line || 0,
			column: loc?.start.column || 0,
			snippet: `@${decoratorName}(...)`,
			suggestion: 'Add @UseGuards(AuthGuard) or @UseGuards(JwtAuthGuard) to secure this route',
		});
	}

	/**
	 * Check if a route call has authentication middleware
	 */
	private checkForAuthMiddleware(node: CallExpression): boolean {
		const handlers = node.arguments.slice(1);

		for (const handler of handlers) {
			if (this.isAuthMiddleware(handler)) {
				return true;
			}

			if (handler.type === 'Identifier') {
				const name = handler.name.toLowerCase();
				if (this.isAuthFunctionName(name)) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Check if a node represents authentication middleware
	 */
	private isAuthMiddleware(node: Node): boolean {
		if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
			const name = node.callee.name.toLowerCase();
			return this.isAuthFunctionName(name);
		}

		if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
			const name = this.getPropertyName(node.callee);
			if (name && this.isAuthFunctionName(name.toLowerCase())) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if a function name indicates authentication
	 */
	private isAuthFunctionName(name: string): boolean {
		const authPatterns = [
			'requireauth',
			'authenticate',
			'auth',
			'protect',
			'authorized',
			'isauthenticated',
			'checkauth',
			'verifytoken',
			'validatejwt',
			'ensureauthenticated',
			'requirelogin',
			'private',
			'authenticated',
			'withauth',
			'useauth',
		];
		return authPatterns.some((pattern) => name.includes(pattern));
	}

	/**
	 * Check if an object is an Express router/app
	 */
	private isExpressRouter(name: string, imports: Map<string, string>): boolean {
		const source = imports.get(name);
		return source?.includes('express') || false;
	}

	/**
	 * Check if an object is a Fastify instance
	 */
	private isFastifyInstance(name: string, imports: Map<string, string>): boolean {
		const source = imports.get(name);
		return source?.includes('fastify') || false;
	}

	/**
	 * Check if an object is a Hono app
	 */
	private isHonoApp(name: string, imports: Map<string, string>): boolean {
		const source = imports.get(name);
		return source?.includes('hono') || false;
	}

	/**
	 * Check if there are NestJS imports
	 */
	private hasNestJsImport(imports: Map<string, string>): boolean {
		for (const source of imports.values()) {
			if (source.includes('@nestjs')) return true;
		}
		return false;
	}

	/**
	 * Get the name of a property from a MemberExpression
	 */
	private getPropertyName(node: MemberExpression): string | null {
		if (node.property.type === 'Identifier') {
			return node.property.name;
		}
		if (node.property.type === 'StringLiteral') {
			return node.property.value;
		}
		return null;
	}

	/**
	 * Get the object name from a MemberExpression
	 */
	private getObjectName(node: MemberExpression): string | null {
		if (node.object.type === 'Identifier') {
			return node.object.name;
		}
		if (node.object.type === 'MemberExpression') {
			return this.getObjectName(node.object);
		}
		return null;
	}

	/**
	 * Extract a code snippet from a node
	 */
	private extractSnippet(): string {
		return '[Route definition]';
	}

	/**
	 * Generate a unique finding ID
	 */
	private generateFindingId(filePath: string, lineNumber: number): string {
		const hash = this.simpleHash(`${filePath}:${lineNumber}`);
		return `AUTH-${hash.substring(0, 8).toUpperCase()}`;
	}

	/**
	 * Simple hash function for generating IDs
	 */
	private simpleHash(str: string): string {
		let hash = 0;
		for (let i = 0; i < str.length; i++) {
			const char = str.charCodeAt(i);
			hash = (hash << 5) - hash + char;
			hash = hash & hash;
		}
		return Math.abs(hash).toString(16);
	}
}
