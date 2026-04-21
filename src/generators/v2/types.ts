// Types and interfaces for Dataset Generator V2

export interface ShareGPTConversation {
  id: string;
  conversations: ShareGPTMessage[];
  metadata: ConversationMetadata;
}

export interface ShareGPTMessage {
  from: "system" | "human" | "gpt" | "tool";
  value: string;
  thinking?: string;
  tool_calls?: ToolCall[];
  tool_results?: ToolResult[];
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, string>;
}

export interface ToolResult {
  tool_call_id: string;
  name: string;
  output: string;
}

export interface ConversationMetadata {
  scenario_id: string;
  category: string;
  subcategory: string;
  difficulty: string;
  tags: string[];
  tools_used: string[];
  has_thinking: boolean;
  has_failures: boolean;
  is_triage?: boolean;
  turn_count: number;
  cve_references: string[];
  estimated_tokens: number;
  generated_at: string;
}

export interface GenerationConfig {
  count: number;
  outputDir: string;
  thinkingRatio: number;
  failureRatio: number;
  minTurns: number;
  maxTurns: number;
  maxTokensPerEntry?: number;  // estimated token limit per conversation
  thinkingStyle?: "field" | "inline";  // 'field' = separate thinking field, 'inline' = embedded <think> tags in value
  categories?: string[];
  difficulties?: string[];
  tags?: string[];
  seed?: number;
}

export interface DatasetQualityReport {
  averageScore: number;
  highQuality: number;
  mediumQuality: number;
  lowQuality: number;
  toolCoverage: number;
  scenarioCoverage: number;
  diversityScore: number;
}

export const DEFAULT_CONFIG: GenerationConfig = {
  count: 2000,
  outputDir: "./datasets",
  thinkingRatio: 0.6,
  failureRatio: 0.35,
  minTurns: 8,
  maxTurns: 15,
  maxTokensPerEntry: 0,        // 0 = no limit
  thinkingStyle: "inline",     // 'inline' = Qwen-native <think> tags in value
  seed: undefined,
};
