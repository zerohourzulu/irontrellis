import type {DynamicStructuredTool} from '@langchain/core/tools';
import type {ToolRegistry,CooperativeExecutor} from './index.mjs';
/** The application fixes identity. Only the configured arguments become model input. */
export declare function createIronTrellisTool(options: Readonly<{registry: ToolRegistry; executor: CooperativeExecutor;
  tool: string; operationId: string; businessKey: string; name?: string}>): DynamicStructuredTool;
export declare function createIronTrellisTools(options: Readonly<{registry: ToolRegistry; executor: CooperativeExecutor;
  operations: readonly Readonly<{tool: string; operationId: string; businessKey: string; name?: string}>[]}>): readonly DynamicStructuredTool[];
