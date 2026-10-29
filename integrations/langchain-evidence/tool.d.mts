import type { Client } from '@modelcontextprotocol/client';
import type { DynamicStructuredTool } from '@langchain/core/tools';
import type * as z from 'zod';
/** The application owns operationId; model arguments contain the resource only. */
export declare function evidenceTool<R extends string>(client: Pick<Client, 'callTool'>, options: Readonly<{ operationId: string; resource: R }>): DynamicStructuredTool<z.ZodObject<{resource: z.ZodLiteral<R>}>, {resource: R}, {resource: R}, string>;
