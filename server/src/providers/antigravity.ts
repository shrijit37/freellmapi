// Antigravity provider — Google Cloud Code Assist (the backend behind the
// Antigravity IDE agent). "API keys" for this platform are OAuth credential
// blobs enrolled through the device flow in routes/oauth.ts (see
// docs/internal-egress-oauth-contract.md §2-3). The decrypted encrypted_key
// plaintext arrives here as `apiKey`; we parse it, mint a fresh access token
// via lib/oauth.ts getValidAccessToken (which refreshes + persists when the
// credential is inside its expiry margin), and translate OpenAI chat
// requests into the Gemini-shaped body the cloudcode-pa endpoint expects.
//
// Wire format verified against CLIProxyAPI
// (internal/runtime/executor/antigravity_executor*.go and
// internal/translator/antigravity/openai/chat-completions/*):
//   POST https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse
//   POST https://cloudcode-pa.googleapis.com/v1internal:generateContent
//   body: {project, model, request:{contents, systemInstruction?, tools?, generationConfig?}}
//   responses are Gemini-shaped envelopes `{response:{candidates:[...],
//   usageMetadata}}` on stream, or `{candidates:[...], usageMetadata}` flat
//   on non-stream (the executor unwraps `response` when present — we accept
//   both spellings).
//
// All outbound calls go through fetchWithTimeout → proxyFetch so per-key
// proxy overrides, global proxy, and the relay-pool egress rotation apply
// automatically.

import type {
  ChatMessage,
  ChatCompletionResponse,
  ChatCompletionChunk,
  ChatToolCall,
  ChatToolDefinition,
  TokenUsage,
} from '@freellmapi/shared/types.js';
import { BaseProvider, providerHttpError, type CompletionOptions, type KeyValidationResult } from './base.js';
import { contentToString } from '../lib/content.js';
import { providerTimeoutMs, streamStallTimeoutMs } from '../lib/provider-timeout.js';
import { resolveMaxTokens } from '../lib/sampling-params.js';
import { sanitizeForGemini } from '../lib/gemini-wire.js';
import { parseOAuthCredential, type OAuthCredential } from '../lib/oauth-credentials.js';
import { getValidAccessToken } from '../lib/oauth.js';
import { recordQuotaObservationsFromResponse, type QuotaObservationContext } from '../services/provider-quota.js';

const API_BASE = 'https://cloudcode-pa.googleapis.com';
const API_VERSION = 'v1internal';

// The native Antigravity client identifies as its hub build. Cloud Code
// rejects newer models for clients below 2.23.0, so this floor stays pinned
// to the version the CLIProxyAPI constants were verified against (cl=1013060670
// belongs to 2.29.0).
const USER_AGENT = 'antigravity/hub/2.29.0 (aidev_client; os_type=linux; arch=x64; cl=1013060670)';

// Function-call parts replayed into history carry Google's documented
// sentinel thought signature — the API didn't produce these calls, so the
// signature check is skipped (same approach as google.ts's
// DUMMY_THOUGHT_SIGNATURE).
const ANTIGRAVITY_THOUGHT_SIGNATURE = 'skip_thought_signature_validator';

interface GeminiPart {
  text?: string;
  thought?: boolean;
  inlineData?: {
    mimeType?: string;
    mime_type?: string;
    data: string;
  };
  thoughtSignature?: string;
  functionCall?: {
    id?: string;
    name?: string;
    args?: unknown;
  };
  functionResponse?: {
    id?: string;
    name?: string;
    response?: unknown;
  };
}

interface GeminiCandidate {
  content?: { role?: string; parts?: GeminiPart[] };
  finishReason?: string;
  finishMessage?: string;
}

interface GeminiUsageMetadata {
  promptTokenCount?: number;
  candidatesTokenCount?: number;
  totalTokenCount?: number;
  thoughtsTokenCount?: number;
  cachedContentTokenCount?: number;
}

/** Antigravity wraps the Gemini payload in a `response` envelope on SSE
 *  chunks; the non-stream :generateContent answer may arrive flat or
 *  wrapped. Normalize to the inner Gemini response. */
interface AntigravityResponse {
  response?: {
    candidates?: GeminiCandidate[];
    usageMetadata?: GeminiUsageMetadata;
    modelVersion?: string;
    responseId?: string;
  };
  candidates?: GeminiCandidate[];
  usageMetadata?: GeminiUsageMetadata;
  modelVersion?: string;
  responseId?: string;
}

function innerResponse(data: AntigravityResponse): {
  candidates?: GeminiCandidate[];
  usageMetadata?: GeminiUsageMetadata;
} {
  if (data.response) return data.response;
  return data;
}

function safeParseObject(raw: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return { value: parsed };
  } catch {
    return { value: raw };
  }
}

function normalizeGeminiArgs(args: unknown): string {
  if (typeof args === 'string') return args;
  return JSON.stringify(args ?? {});
}

function toGeminiFinishReason(finishReason?: string): string {
  const r = (finishReason ?? '').toUpperCase();
  if (!r) return 'stop';
  if (r === 'MAX_TOKENS') return 'length';
  if (r === 'SAFETY' || r === 'RECITATION' || r === 'BLOCKLIST' || r === 'PROHIBITED_CONTENT' || r === 'SPII') {
    return 'content_filter';
  }
  return 'stop';
}

/** Pull the OAuth credential out of the decrypted key blob and mint a live
 *  access token. Throws providerHttpError(401) for non-OAuth plaintext so the
 *  router benches the key normally; token-refresh failures propagate from
 *  getValidAccessToken as OAuthError. */
async function resolveAccessToken(
  apiKey: string,
  quotaContext?: QuotaObservationContext,
): Promise<{ accessToken: string; credential: OAuthCredential }> {
  const cred = parseOAuthCredential(apiKey);
  if (!cred || cred.provider !== 'antigravity') {
    throw providerHttpError(
      new Response(null, { status: 401 }),
      'Antigravity key is not a valid OAuth credential (expected an antigravity device-flow blob)',
    );
  }
  const { accessToken, credential } = await getValidAccessToken(apiKey, quotaContext?.keyId);
  return { accessToken, credential };
}

/** Extract a base64 inlineData part from an OpenAI image_url block (data:
 *  URLs only — the Antigravity wire has no remote-URL fetch, matching
 *  CLIProxyAPI's NormalizeOpenAIFileData behavior). Returns null for remote
 *  URLs and malformed payloads. */
function imageUrlToInlineData(url: string): { mimeType: string; data: string } | null {
  const dataMatch = /^data:([^;,]+)?(;base64)?,(.*)$/s.exec(url);
  if (!dataMatch) return null;
  const mimeType = dataMatch[1] || 'application/octet-stream';
  const isBase64 = Boolean(dataMatch[2]);
  const payload = dataMatch[3] ?? '';
  const data = isBase64
    ? payload
    : Buffer.from(decodeURIComponent(payload)).toString('base64');
  return { mimeType, data };
}

function extractImageUrl(block: unknown): string | undefined {
  const iu = (block as { image_url?: unknown })?.image_url;
  if (typeof iu === 'string') return iu;
  if (iu && typeof (iu as { url?: unknown }).url === 'string') return (iu as { url: string }).url;
  return undefined;
}

type GeminiContent = { role: 'user' | 'model'; parts: GeminiPart[] };

/** Translate OpenAI ChatMessage[] into the Antigravity `request` payload:
 *  leading system/developer turns fold into systemInstruction (CLIProxyAPI
 *  demotes later ones into user turns prefixed with the system text);
 *  assistant tool_calls become functionCall parts carrying the sentinel
 *  thoughtSignature; tool results become functionResponse parts on a user
 *  turn scoped to the preceding assistant message. */
function toAntigravityRequest(messages: ChatMessage[]): {
  contents: GeminiContent[];
  systemInstruction?: { role: 'user'; parts: GeminiPart[] };
} {
  const systemParts: GeminiPart[] = [];
  const contentItems: GeminiContent[] = [];
  let hasEncounteredConversation = false;

  const toolNameByCallId = new Map<string, string>();
  for (const m of messages) {
    for (const tc of m.tool_calls ?? []) {
      toolNameByCallId.set(tc.id, tc.function.name);
    }
  }

  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    // The OpenAI wire admits 'developer' as a system-role alias even though
    // ChatMessage's union only spells 'system'; widen once so both spellings
    // take the system-instruction path.
    const role: string = m.role;
    const content = m.content;

    if ((role === 'system' || role === 'developer') && !hasEncounteredConversation) {
      const text = contentToString(content);
      if (text.length > 0) systemParts.push({ text });
      continue;
    }

    if (role === 'user' || role === 'system' || role === 'developer') {
      hasEncounteredConversation = true;
      const isDemotedSystem = role === 'system' || role === 'developer';
      const parts: GeminiPart[] = [];
      const text = contentToString(content);
      if (text.length > 0) {
        parts.push({ text: isDemotedSystem ? `[System instruction]: ${text}` : text });
      }
      if (Array.isArray(content)) {
        for (const block of content) {
          const type = (block as { type?: string })?.type;
          if (type !== 'image_url' && type !== 'image') continue;
          const url = extractImageUrl(block);
          if (!url) continue;
          const inlineData = imageUrlToInlineData(url);
          if (inlineData) parts.push({ inlineData });
        }
      }
      if (parts.length > 0) {
        contentItems.push({ role: 'user', parts });
      }
      continue;
    }

    if (role === 'assistant') {
      hasEncounteredConversation = true;
      const parts: GeminiPart[] = [];

      const reasoning = (m as { reasoning_content?: unknown }).reasoning_content;
      if (typeof reasoning === 'string' && reasoning.length > 0) {
        parts.push({ text: reasoning, thought: true });
      }
      const assistantText = contentToString(content);
      if (assistantText.length > 0) parts.push({ text: assistantText });

      const calls = m.tool_calls ?? [];
      for (const call of calls) {
        parts.push({
          thoughtSignature: ANTIGRAVITY_THOUGHT_SIGNATURE,
          functionCall: {
            id: call.id,
            name: call.function.name,
            args: safeParseObject(call.function.arguments),
          },
        });
      }

      if (parts.length > 0) {
        contentItems.push({ role: 'model', parts });
      }

      // Function responses ride on a following user turn, scoped to this
      // assistant message (CLIProxyAPI collects tool messages up to the next
      // assistant turn).
      if (calls.length > 0) {
        const responseParts: GeminiPart[] = [];
        const responseByCallId = new Map<string, string>();
        for (let j = i + 1; j < messages.length; j++) {
          const next = messages[j];
          if (next.role === 'assistant') break;
          if (next.role === 'tool' && next.tool_call_id) {
            responseByCallId.set(next.tool_call_id, contentToString(next.content));
          }
        }
        for (const call of calls) {
          const response = responseByCallId.get(call.id) ?? '{}';
          responseParts.push({
            functionResponse: {
              id: call.id,
              name: call.function.name,
              // Kept as a string (not parsed) — CLIProxyAPI notes parsing it
              // into JSON can trigger an upstream 400.
              response: { result: response },
            },
          });
        }
        if (responseParts.length > 0) {
          contentItems.push({ role: 'user', parts: responseParts });
        }
      }
      continue;
    }

    if (role === 'tool') {
      // Orphan tool result (no preceding assistant tool_calls — e.g. history
      // truncated upstream). Forward as a plain user turn so the model still
      // sees the output.
      hasEncounteredConversation = true;
      const toolName = m.name ?? toolNameByCallId.get(m.tool_call_id ?? '') ?? 'tool';
      const response = contentToString(content);
      contentItems.push({
        role: 'user',
        parts: [{
          functionResponse: {
            id: m.tool_call_id,
            name: toolName,
            response: { result: response },
          },
        }],
      });
    }
  }

  return {
    contents: contentItems,
    systemInstruction: systemParts.length > 0
      ? { role: 'user', parts: systemParts }
      : undefined,
  };
}

/** OpenAI tools → Antigravity request.tools: function declarations use
 *  `parametersJsonSchema` (Antigravity's spelling, per CLIProxyAPI's rename of
 *  `parameters`), and the google_search pseudo-tool maps to a native
 *  `{googleSearch:{}}` entry. */
function toAntigravityTools(tools?: ChatToolDefinition[]): Array<Record<string, unknown>> | undefined {
  if (!tools || tools.length === 0) return undefined;

  const functionDeclarations: Array<Record<string, unknown>> = [];
  let grounding = false;
  for (const t of tools) {
    const name = t.function.name.toLowerCase();
    if (name === 'google_search' || name === 'googlesearch' || name === 'google_search_retrieval') {
      grounding = true;
      continue;
    }
    const decl: Record<string, unknown> = {
      name: t.function.name,
      description: t.function.description,
      parametersJsonSchema: sanitizeForGemini(t.function.parameters) ?? { type: 'object', properties: {} },
    };
    functionDeclarations.push(decl);
  }

  const out: Array<Record<string, unknown>> = [];
  if (functionDeclarations.length > 0) out.push({ functionDeclarations });
  if (grounding) out.push({ googleSearch: {} });
  return out.length > 0 ? out : undefined;
}

function extractText(parts: GeminiPart[] | undefined): string | null {
  if (!parts) return null;
  const text = parts
    .filter(p => p.thought !== true)
    .filter(p => !p.functionCall && !p.functionResponse && !p.inlineData)
    .map(p => p.text ?? '')
    .join('');
  return text.length > 0 ? text : null;
}

function extractReasoningContent(parts: GeminiPart[] | undefined): string | null {
  if (!parts) return null;
  const text = parts
    .filter(p => p.thought === true)
    .map(p => p.text ?? '')
    .join('');
  return text.length > 0 ? text : null;
}

function extractToolCalls(parts: GeminiPart[] | undefined, firstIndex = 0): ChatToolCall[] {
  const calls: ChatToolCall[] = [];
  if (!parts) return calls;

  let fallbackIndex = firstIndex;
  for (const part of parts) {
    if (!part.functionCall?.name) continue;
    const id = part.functionCall.id ?? `call_${Date.now()}_${fallbackIndex++}`;
    calls.push({
      id,
      type: 'function',
      function: {
        name: part.functionCall.name,
        arguments: normalizeGeminiArgs(part.functionCall.args),
      },
      thought_signature: part.thoughtSignature,
    });
  }
  return calls;
}

function extractImages(parts: GeminiPart[] | undefined): Array<{ type: 'image_url'; image_url: { url: string } }> {
  const images: Array<{ type: 'image_url'; image_url: { url: string } }> = [];
  for (const part of parts ?? []) {
    const data = part.inlineData?.data;
    if (!data) continue;
    const mimeType = part.inlineData?.mimeType ?? part.inlineData?.mime_type ?? 'image/png';
    images.push({ type: 'image_url', image_url: { url: `data:${mimeType};base64,${data}` } });
  }
  return images;
}

function usageFromMetadata(usage?: GeminiUsageMetadata): TokenUsage {
  const prompt = usage?.promptTokenCount ?? 0;
  const thoughts = usage?.thoughtsTokenCount ?? 0;
  return {
    prompt_tokens: prompt,
    completion_tokens: (usage?.candidatesTokenCount ?? 0) + thoughts,
    total_tokens: usage?.totalTokenCount ?? (prompt + (usage?.candidatesTokenCount ?? 0) + thoughts),
    ...(thoughts > 0 ? { completion_tokens_details: { reasoning_tokens: thoughts } } : {}),
    ...(usage?.cachedContentTokenCount
      ? { prompt_tokens_details: { cached_tokens: usage.cachedContentTokenCount } }
      : {}),
  };
}

function antigravityHttpError(res: Response, body: unknown): Error {
  return providerHttpError(res, `Antigravity request failed (HTTP ${res.status})`, body);
}

export interface AntigravityProviderOptions {
  /** Per-provider HTTP timeout override. Antigravity frontier models can
   *  prefill long prompts for tens of seconds; mirrors OpenAICompatProvider. */
  timeoutMs?: number;
}

export class AntigravityProvider extends BaseProvider {
  readonly platform = 'antigravity' as const;
  readonly name = 'Antigravity (Google Cloud Code Assist)';
  private readonly timeoutMs: number;

  constructor(opts: AntigravityProviderOptions = {}) {
    super();
    this.timeoutMs = providerTimeoutMs('antigravity', opts.timeoutMs ?? 60000);
  }

  private buildBody(
    credential: OAuthCredential,
    modelId: string,
    messages: ChatMessage[],
    options?: CompletionOptions,
  ): Record<string, unknown> {
    const translated = toAntigravityRequest(messages);
    const projectId = typeof credential.project_id === 'string' ? credential.project_id : '';

    const tools = toAntigravityTools(options?.tools);
    const request: Record<string, unknown> = {
      contents: translated.contents,
      generationConfig: {
        temperature: options?.temperature,
        maxOutputTokens: resolveMaxTokens(this.platform, options?.max_tokens, options?.contextBudget),
        topP: options?.top_p,
      },
      tools,
    };
    if (translated.systemInstruction) request.systemInstruction = translated.systemInstruction;

    const body: Record<string, unknown> = {
      project: projectId,
      model: modelId,
      request,
    };
    return body;
  }

  private headers(accessToken: string): Record<string, string> {
    return {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'User-Agent': USER_AGENT,
    };
  }

  async chatCompletion(
    apiKey: string,
    messages: ChatMessage[],
    modelId: string,
    options?: CompletionOptions,
    quotaContext?: QuotaObservationContext,
  ): Promise<ChatCompletionResponse> {
    const { accessToken, credential } = await resolveAccessToken(apiKey, quotaContext);
    const body = this.buildBody(credential, modelId, messages, options);

    const url = `${API_BASE}/${API_VERSION}:generateContent`;
    const res = await this.fetchWithTimeout(url, {
      method: 'POST',
      headers: this.headers(accessToken),
      body: JSON.stringify(body),
      // 'request' bounds: the deadline covers the body read too, so a 200
      // whose body hangs aborts instead of stalling res.json() forever.
    }, options?.timeoutMs ?? this.timeoutMs, { signal: options?.signal, timeoutBounds: 'request' });

    recordQuotaObservationsFromResponse(res, {
      platform: this.platform,
      keyId: quotaContext?.keyId,
      providerAccountId: quotaContext?.providerAccountId,
      modelId,
      quotaPoolKey: quotaContext?.quotaPoolKey,
      endpoint: 'chat/completions',
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw antigravityHttpError(res, err);
    }

    const data = (await res.json()) as AntigravityResponse;
    const inner = innerResponse(data);
    const candidate = inner.candidates?.[0];
    const parts = candidate?.content?.parts;
    const toolCalls = extractToolCalls(parts);
    const text = extractText(parts);
    const reasoningContent = extractReasoningContent(parts);
    const images = extractImages(parts);

    return {
      id: this.makeId(),
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: modelId,
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: text ?? (images.length > 0 ? '' : null),
          ...(reasoningContent ? { reasoning_content: reasoningContent } : {}),
          ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
          ...(images.length > 0 ? { images } : {}),
        } as ChatCompletionResponse['choices'][number]['message'],
        finish_reason: toolCalls.length > 0 ? 'tool_calls' : toGeminiFinishReason(candidate?.finishReason),
      }],
      usage: usageFromMetadata(inner.usageMetadata),
      _routed_via: { platform: 'antigravity', model: modelId },
    };
  }

  async *streamChatCompletion(
    apiKey: string,
    messages: ChatMessage[],
    modelId: string,
    options?: CompletionOptions,
    quotaContext?: QuotaObservationContext,
  ): AsyncGenerator<ChatCompletionChunk> {
    const { accessToken, credential } = await resolveAccessToken(apiKey, quotaContext);
    const body = this.buildBody(credential, modelId, messages, options);

    const url = `${API_BASE}/${API_VERSION}:streamGenerateContent?alt=sse`;
    const res = await this.fetchWithTimeout(url, {
      method: 'POST',
      headers: this.headers(accessToken),
      body: JSON.stringify(body),
      // Default 'headers' bounds: the deadline dies at response headers, and
      // the client signal + stall watchdog own the stream from there.
    }, options?.timeoutMs ?? this.timeoutMs, { signal: options?.signal });

    recordQuotaObservationsFromResponse(res, {
      platform: this.platform,
      keyId: quotaContext?.keyId,
      providerAccountId: quotaContext?.providerAccountId,
      modelId,
      quotaPoolKey: quotaContext?.quotaPoolKey,
      endpoint: 'chat/completions',
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw antigravityHttpError(res, err);
    }

    const reader = res.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();
    const id = this.makeId();
    let buffer = '';
    let emittedFinish = false;
    let sawToolCalls = false;
    let nextToolIndex = 0;

    const inactivityTimeoutMs = streamStallTimeoutMs(this.platform);
    const firstByteMs = this.firstByteBudgetMs(options?.timeoutMs ?? this.timeoutMs, inactivityTimeoutMs);
    let awaitingFirstByte = true;

    try {
      while (true) {
        const { done, value } = awaitingFirstByte
          ? await this.readWithStallTimeout(() => reader.read(), firstByteMs, this.firstByteTimeoutMessage(firstByteMs))
          : await this.readWithStallTimeout(() => reader.read(), inactivityTimeoutMs);
        awaitingFirstByte = false;
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith('data:')) continue;
          const raw = trimmed.slice(5).replace(/^ /, '');
          if (raw === '[DONE]') {
            if (!emittedFinish) {
              emittedFinish = true;
              yield {
                id,
                object: 'chat.completion.chunk',
                created: Math.floor(Date.now() / 1000),
                model: modelId,
                choices: [{
                  index: 0,
                  delta: {},
                  finish_reason: sawToolCalls ? 'tool_calls' : 'stop',
                }],
              };
            }
            return;
          }

          let chunk: AntigravityResponse;
          try {
            chunk = JSON.parse(raw) as AntigravityResponse;
          } catch {
            continue;
          }
          const inner = innerResponse(chunk);
          const candidate = inner.candidates?.[0];
          const parts = candidate?.content?.parts ?? [];

          const text = extractText(parts);
          const reasoningContent = extractReasoningContent(parts);
          const toolCalls = extractToolCalls(parts, nextToolIndex).map(call => ({ ...call, index: nextToolIndex++ }));

          if ((text && text.length > 0) || (reasoningContent && reasoningContent.length > 0) || toolCalls.length > 0) {
            sawToolCalls = sawToolCalls || toolCalls.length > 0;
            yield {
              id,
              object: 'chat.completion.chunk',
              created: Math.floor(Date.now() / 1000),
              model: modelId,
              choices: [{
                index: 0,
                delta: {
                  role: 'assistant',
                  ...(text ? { content: text } : {}),
                  ...(reasoningContent ? { reasoning_content: reasoningContent } : {}),
                  ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
                },
                finish_reason: null,
              }],
            };
          }

          if (candidate?.finishReason && !emittedFinish) {
            emittedFinish = true;
            yield {
              id,
              object: 'chat.completion.chunk',
              created: Math.floor(Date.now() / 1000),
              model: modelId,
              choices: [{
                index: 0,
                delta: {},
                finish_reason: sawToolCalls ? 'tool_calls' : toGeminiFinishReason(candidate.finishReason),
              }],
            };
            return;
          }
        }
      }
    } finally {
      // Runs on normal completion, early returns, AND generator abandonment —
      // same cleanup contract as google.ts's stream reader.
      reader.cancel().catch(() => { /* upstream already gone */ });
    }

    // Abrupt EOF without [DONE] or finishReason = truncated upstream; mirror
    // google.ts/readSseStream so the fallback loop fails over instead of
    // reporting a half-written answer as complete.
    if (!emittedFinish) {
      throw new Error(`${this.name} stream ended unexpectedly (no [DONE], no finish_reason) — connection reset or truncated upstream`);
    }
  }

  async validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult> {
    const { accessToken } = await resolveAccessToken(apiKey, quotaContext);

    // loadCodeAssist is the enrollment probe CLIProxyAPI uses: 200 means the
    // OAuth token is accepted by Cloud Code; 401/403 mean the grant is dead.
    const res = await this.fetchWithTimeout(
      `${API_BASE}/${API_VERSION}:loadCodeAssist`,
      {
        method: 'POST',
        headers: this.headers(accessToken),
        body: JSON.stringify({ metadata: { ideType: 'ANTIGRAVITY' } }),
      },
      10000,
      { signal: undefined, timeoutBounds: 'request' },
    );
    recordQuotaObservationsFromResponse(res, {
      platform: this.platform,
      keyId: quotaContext?.keyId,
      providerAccountId: quotaContext?.providerAccountId,
      modelId: quotaContext?.modelId,
      quotaPoolKey: quotaContext?.quotaPoolKey,
      endpoint: 'loadCodeAssist',
    });
    if (res.ok) return true;

    let detail = '';
    try {
      const body = (await res.json()) as { error?: { message?: string }; message?: string };
      detail = body?.error?.message ?? body?.message ?? '';
    } catch { /* non-JSON error body */ }

    if (res.status === 401 || res.status === 403) {
      return {
        valid: false,
        error: `Antigravity key validation failed (HTTP ${res.status})${detail ? `: ${detail}` : ''}`,
      };
    }

    // Anything else (5xx, region blocks, transient) is inconclusive — throw
    // so health records 'error' without disabling a usable key.
    throw new Error(
      `Antigravity key validation inconclusive (HTTP ${res.status})${detail ? `: ${detail}` : ''}`,
    );
  }
}
