import type { LocalEvidenceTool } from '@ramex-labs/irontrellis';
import type { McpServer } from '@modelcontextprotocol/server';
import type { serveStdio } from '@modelcontextprotocol/server/stdio';
import type { Readable, Writable } from 'node:stream';
export declare function createGatewayServer(tool: LocalEvidenceTool): McpServer;
export declare function serveGateway(tool: LocalEvidenceTool, streams?: Readonly<{input?: Readable; output?: Writable}>): ReturnType<typeof serveStdio>;
