# ACP gateway

ACP's governance controls applied to LLM traffic, with **no change to the agent's code**.

Point an agent's base URL at the gateway and give it a gateway key. The gateway identifies the agent, checks
the request, forwards it to the model provider with the real provider key, checks the answer, and writes an
audit row.

```
agent ──(gateway key)──▶ ACP gateway ──(provider key)──▶ OpenAI / Azure / vLLM / any OpenAI-compatible API
                             │
                             ├─ Q33 rate limit            ├─ Q30 tool permissions (on the model's tool calls)
                             ├─ Q29 injection firewall    ├─ Q25 PII scan / redaction (both directions)
                             ├─ Q34 data classification   └─ audit row (hash-chained, no message text)
                             └─ pause switch from the ACP dashboard
```

It is a separate tool from the ACP SDK and from BlueDefence. Use the gateway to cover every agent on day one;
use the SDK inside the agents that need per-step control and regulatory evidence.

| | Gateway (this repo) | SDK (`acp-sdk`) |
|---|---|---|
| Change to agent code | None: a base URL and a key | Import and wrap |
| Sees | Prompts, answers, tool calls on the wire | Every step, memory, cost, loops |
| Covers agents you cannot modify | Yes, if they accept a base URL | No |

## Quick start

```bash
pip install .                                   # needs read access to mahi80/rbi for acp-sdk
python -m acp_gateway new-key                   # prints a gateway key; put it in an env var
cp gateway.example.yaml gateway.yaml            # edit upstreams and clients
export OPENAI_API_KEY=...  GW_KEY_LOAN=...      # secrets live in the environment, never in the file
export ACP_GATEWAY_CONFIG=gateway.yaml
python -m acp_gateway check                     # validate
python -m acp_gateway                           # serve on 127.0.0.1:8080
```

In the agent:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=<the gateway key>
```

## Modes (per client)

| Mode | Personal data | Prompt injection | Denied tool call | Use it when |
|---|---|---|---|---|
| `observe` | recorded | recorded | recorded | First weeks. Nothing is changed or blocked. |
| `redact` | masked, both directions | request refused (403) | removed from the answer, agent told | Normal operation |
| `block` | request refused / answer withheld (403) | request refused | removed from the answer | Strict clients |

The operator's pause and nothing else applies in `observe`: rate limits and the model allowlist are recorded
but not enforced there.

`fail: open` (default) forwards traffic if a check itself crashes; `fail: closed` answers 503. In `observe`
nothing is ever blocked, including on a failed check.

## Streaming

- `observe`: bytes are passed through as they arrive; the answer is reassembled on the side and checked after
  the last chunk.
- `redact` / `block`: the gateway asks the provider for the whole answer, checks it, then returns it as a
  stream of chunks. The agent gets a valid stream, but not token by token. A tool call or personal data
  cannot be taken back once streamed, so correctness comes first in 0.1. Windowed streaming is planned.

## Audit

One row per request in `audit_path` (JSONL, mode 0600), hash-chained:

```bash
python -m acp_gateway verify /var/lib/acp-gateway/audit.jsonl
```

Rows hold the client, model, action, reason, timings, token count and findings (`control`, `kind`, `where`,
`count`). They never hold prompt or answer text, gateway keys or provider keys.

## ACP dashboard (optional)

Set `ACP_DASHBOARD_URL` and `ACP_API_KEY`. Each client is registered as an agent (framework `acp-gateway`),
heartbeats, and ships its audit rows. If the dashboard pauses the agent, the gateway answers that client with
423 until it is unpaused. The dashboard is never on the request path: if it is down, traffic continues and
rows queue (bounded) while the local file keeps everything.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `ACP_GATEWAY_CONFIG` | — | Path to the YAML file |
| `ACP_GATEWAY_HOST` / `ACP_GATEWAY_PORT` | `127.0.0.1` / `8080` | Bind address. Put TLS in front (ingress / load balancer). |
| `ACP_GATEWAY_AUDIT` | — | Audit file, if not set in the YAML |
| `ACP_DASHBOARD_URL`, `ACP_API_KEY` | — | Link to an ACP dashboard |

## Limits (0.1)

- OpenAI-compatible chat completions and embeddings only. Not yet: the Responses API, Anthropic's
  `/v1/messages`, an MCP proxy, an agent inventory page.
- A gateway only sees agents that are pointed at it. Enforce that with egress rules that allow model
  providers only via the gateway.
- Detection is rule-based (the SDK's patterns). Expect false positives on real traffic: run in `observe`
  first and tune before enforcing.
- Rate limits and the pause state are per process. Run one replica, or expect limits to be per replica, until
  shared state (Redis) is added.
- `require_approval` tools are held back like denied ones: there is no approval round-trip yet.
- The SDK's e-mail pattern is slow on adversarial text; the gateway swaps in a linear one. The SDK itself
  should be fixed.

## Tests

```bash
pip install pytest && python -m pytest tests -q
```
