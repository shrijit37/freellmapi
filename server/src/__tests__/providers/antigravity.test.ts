import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AntigravityProvider } from '../../providers/antigravity.js';
import { OAuthError } from '../../lib/oauth.js';
import type { OAuthCredential } from '../../lib/oauth-credentials.js';

// Keep the OAuth hot path hermetic: chat/validate tests stub the token mint;
// credential-parse tests exercise the real parseOAuthCredential inside the
// provider before getValidAccessToken is ever reached.
vi.mock('../../lib/oauth.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../lib/oauth.js')>();
  return {
    ...actual,
    getValidAccessToken: vi.fn(),
  };
});

import { getValidAccessToken } from '../../lib/oauth.js';

const mockGetValidAccessToken = vi.mocked(getValidAccessToken);

function credential(overrides: Partial<OAuthCredential> = {}): OAuthCredential {
  return {
    v: 1,
    provider: 'antigravity',
    access_token: 'ya29.test-access-token',
    refresh_token: '1//refresh',
    expires_at: Date.now() + 60 * 60 * 1000,
    email: 'user@example.com',
    project_id: 'cloud-12345',
    ...overrides,
  };
}

function credentialJson(overrides: Partial<OAuthCredential> = {}): string {
  return JSON.stringify(credential(overrides));
}

function stubToken(overrides: Partial<OAuthCredential> = {}) {
  const cred = credential(overrides);
  mockGetValidAccessToken.mockResolvedValue({ accessToken: cred.access_token, credential: cred });
  return cred;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function sseResponse(frames: string[]): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const encoder = new TextEncoder();
      for (const frame of frames) controller.enqueue(encoder.encode(frame));
      controller.close();
    },
  });
  return new Response(stream, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
}

async function collect<T>(gen: AsyncGenerator<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const c of gen) out.push(c);
  return out;
}

describe('AntigravityProvider', () => {
  let provider: AntigravityProvider;

  beforeEach(() => {
    vi.clearAllMocks();
    provider = new AntigravityProvider();
    stubToken();
  });

  it('has platform antigravity and a descriptive name', () => {
    expect(provider.platform).toBe('antigravity');
    expect(provider.name).toContain('Antigravity');
  });

  it('rejects a non-OAuth api key plaintext with an HTTP 401 error', async () => {
    await expect(
      provider.chatCompletion('sk-static-key', [{ role: 'user', content: 'hi' }], 'gemini-3-pro-high'),
    ).rejects.toMatchObject({ status: 401 });
    expect(mockGetValidAccessToken).not.toHaveBeenCalled();
  });

  it('rejects an OAuth blob for a different provider', async () => {
    const foreign = JSON.stringify({ v: 1, provider: 'devin', access_token: 'x', expires_at: Date.now() + 1000 });
    await expect(
      provider.chatCompletion(foreign, [{ role: 'user', content: 'hi' }], 'gemini-3-pro-high'),
    ).rejects.toMatchObject({ status: 401 });
    expect(mockGetValidAccessToken).not.toHaveBeenCalled();
  });

  it('propagates OAuthError from the token hot path', async () => {
    mockGetValidAccessToken.mockRejectedValue(new OAuthError('refresh_failed', 'refresh token revoked'));
    await expect(
      provider.chatCompletion(credentialJson(), [{ role: 'user', content: 'hi' }], 'gemini-3-pro-high'),
    ).rejects.toThrow(OAuthError);
  });

  it('posts the Antigravity envelope to :generateContent with Bearer + hub UA', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValueOnce(jsonResponse({
      candidates: [{ content: { role: 'model', parts: [{ text: 'Hello!' }] }, finishReason: 'STOP' }],
      usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5, totalTokenCount: 15 },
    }));

    const result = await provider.chatCompletion(
      credentialJson(),
      [
        { role: 'system', content: 'Be terse.' },
        { role: 'user', content: 'Hi' },
      ],
      'gemini-3-pro-high',
    );

    expect(result.object).toBe('chat.completion');
    expect(result.choices[0].message.content).toBe('Hello!');
    expect(result.choices[0].finish_reason).toBe('stop');
    expect(result.usage.prompt_tokens).toBe(10);
    expect(result.usage.total_tokens).toBe(15);
    expect(result._routed_via).toEqual({ platform: 'antigravity', model: 'gemini-3-pro-high' });

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloudcode-pa.googleapis.com/v1internal:generateContent');
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer ya29.test-access-token');
    expect(headers['User-Agent']).toContain('antigravity/hub/2.29.0');
    expect(headers['User-Agent']).toContain('aidev_client');

    const body = JSON.parse(init.body as string) as {
      project: string;
      model: string;
      request: {
        contents: Array<{ role: string; parts: Array<{ text?: string }> }>;
        systemInstruction?: { parts: Array<{ text?: string }> };
      };
    };
    expect(body.project).toBe('cloud-12345');
    expect(body.model).toBe('gemini-3-pro-high');
    expect(body.request.systemInstruction?.parts[0]?.text).toBe('Be terse.');
    expect(body.request.contents).toEqual([
      { role: 'user', parts: [{ text: 'Hi' }] },
    ]);
  });

  it('maps assistant tool_calls to functionCall parts and tool results to functionResponse', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValueOnce(jsonResponse({
      candidates: [{
        content: { role: 'model', parts: [{ functionCall: { name: 'get_weather', args: { city: 'Paris' } } }] },
        finishReason: 'STOP',
      }],
      usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 },
    }));

    const result = await provider.chatCompletion(
      credentialJson(),
      [
        { role: 'user', content: 'weather?' },
        {
          role: 'assistant',
          content: null,
          tool_calls: [{
            id: 'call_1',
            type: 'function',
            function: { name: 'get_weather', arguments: '{"city":"Paris"}' },
          }],
        },
        { role: 'tool', tool_call_id: 'call_1', content: '{"temp":20}' },
      ],
      'gemini-3-pro-high',
      { tools: [{ type: 'function', function: { name: 'get_weather', description: 'w', parameters: { type: 'object' } } }] },
    );

    const body = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string) as {
      request: {
        contents: Array<{ role: string; parts: Array<Record<string, unknown>> }>;
        tools?: Array<Record<string, unknown>>;
      };
    };
    const modelTurn = body.request.contents.find(c => c.role === 'model');
    const fc = modelTurn?.parts[0]?.functionCall as { name: string; args: { city: string }; id?: string };
    expect(fc.name).toBe('get_weather');
    expect(fc.args.city).toBe('Paris');
    // Sentinel thought signature rides every replayed functionCall.
    expect(modelTurn?.parts[0]?.thoughtSignature).toBe('skip_thought_signature_validator');

    const responseTurn = body.request.contents.find(c =>
      c.parts.some(p => p.functionResponse));
    const fr = responseTurn?.parts[0]?.functionResponse as { name: string; response: { result: string } };
    expect(fr.name).toBe('get_weather');
    expect(fr.response.result).toBe('{"temp":20}');

    expect(body.request.tools).toEqual([{
      functionDeclarations: [{
        name: 'get_weather',
        description: 'w',
        parametersJsonSchema: { type: 'object' },
      }],
    }]);

    // Response side: functionCall part maps back to an OpenAI tool_call.
    const call = result.choices[0].message.tool_calls?.[0];
    expect(call?.function.name).toBe('get_weather');
    expect(call?.function.arguments).toBe('{"city":"Paris"}');
    expect(result.choices[0].finish_reason).toBe('tool_calls');
  });

  it('accepts the `response`-wrapped envelope on non-stream responses', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(jsonResponse({
      response: {
        candidates: [{ content: { role: 'model', parts: [{ text: 'wrapped' }] }, finishReason: 'MAX_TOKENS' }],
        usageMetadata: { promptTokenCount: 3, candidatesTokenCount: 4, totalTokenCount: 7 },
      },
    }));

    const result = await provider.chatCompletion(
      credentialJson(),
      [{ role: 'user', content: 'hi' }],
      'gemini-3-pro-high',
    );
    expect(result.choices[0].message.content).toBe('wrapped');
    expect(result.choices[0].finish_reason).toBe('length');
    expect(result.usage.total_tokens).toBe(7);
  });

  it('throws providerHttpError on upstream non-OK', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(jsonResponse({ error: { message: 'quota exceeded' } }, 429));
    await expect(
      provider.chatCompletion(credentialJson(), [{ role: 'user', content: 'hi' }], 'gemini-3-pro-high'),
    ).rejects.toMatchObject({ status: 429 });
  });

  it('streams SSE chunks to OpenAI deltas and finishes on finishReason', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(sseResponse([
      'data: {"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"Hel"}]}}]}}\n\n',
      'data: {"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"lo"},{"text":" thinking","thought":true}]}}]}}\n\n',
      'data: {"response":{"candidates":[{"content":{"role":"model","parts":[]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":3,"totalTokenCount":5}}}\n\n',
    ]));

    const chunks = await collect(provider.streamChatCompletion(
      credentialJson(),
      [{ role: 'user', content: 'Hi' }],
      'gemini-3-pro-high',
    ));

    const text = chunks.map(c => c.choices[0].delta.content ?? '').join('');
    expect(text).toBe('Hello');
    const reasoning = chunks.map(c => (c.choices[0].delta as { reasoning_content?: string }).reasoning_content ?? '').join('');
    expect(reasoning).toBe(' thinking');
    expect(chunks[chunks.length - 1].choices[0].finish_reason).toBe('stop');
    expect(chunks[chunks.length - 1].choices[0].delta.content).toBeUndefined();
  });

  it('streams to :streamGenerateContent?alt=sse', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValueOnce(sseResponse([
      'data: {"response":{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"STOP"}]}}\n\n',
    ]));
    await collect(provider.streamChatCompletion(
      credentialJson(),
      [{ role: 'user', content: 'Hi' }],
      'gemini-3-pro-high',
    ));
    expect((fetchSpy.mock.calls[0][0] as string)).toBe(
      'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse',
    );
  });

  it('throws on abrupt EOF without finish_reason or [DONE]', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(sseResponse([
      'data: {"response":{"candidates":[{"content":{"parts":[{"text":"partial"}]}}]}}\n\n',
    ]));
    await expect(collect(provider.streamChatCompletion(
      credentialJson(),
      [{ role: 'user', content: 'Hi' }],
      'gemini-3-pro-high',
    ))).rejects.toThrow(/ended unexpectedly/);
  });

  it('validateKey posts loadCodeAssist and returns true on 200', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValueOnce(jsonResponse({ cloudaicompanionProject: 'p1' }));
    const result = await provider.validateKey(credentialJson());
    expect(result).toBe(true);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist');
    const body = JSON.parse(init.body as string) as { metadata: { ideType: string } };
    expect(body.metadata.ideType).toBe('ANTIGRAVITY');
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer ya29.test-access-token');
  });

  it('validateKey returns invalid:false on 401', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(jsonResponse({ error: { message: 'unauthorized' } }, 401));
    const result = await provider.validateKey(credentialJson());
    expect(result).toMatchObject({ valid: false });
  });

  it('validateKey throws on inconclusive 500', async () => {
    vi.spyOn(global, 'fetch').mockResolvedValueOnce(jsonResponse({ error: { message: 'boom' } }, 500));
    await expect(provider.validateKey(credentialJson())).rejects.toThrow(/inconclusive/);
  });
});
