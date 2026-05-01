package main

// Natural-language → rule HCL via a connected LLM provider.
// Reuses the operator's existing Claude/Codex OAuth credentials so
// there's no separate API key to manage.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const ruleSystemPrompt = `You edit clawpatrol gateway policy expressed in HCL.

The input is an HCL document containing zero or more ` + "`rule`" + ` blocks.
Output the FULL updated document in the same shape — only ` + "`rule`" + `
blocks at the top level.

A rule block:

  rule {
    host    = "api.example.com"   # required, exact host or glob ("*.example.com")
    device  = "10.55.0.2"         # optional — scopes the rule to one device IP
    port    = 443                  # optional, default 443
    action  = "deny"               # optional: "" (allow, default) | "deny"
    reason  = "explain why"        # optional, shown in deny logs / HITL prompts
    auth    = "claude"             # optional integration name to inject auth for
    body    = true                 # optional, enable request-body scan/swap
    upstream = "real-host"         # optional, rewrite the upstream hostname

    headers = {                    # optional map — add/override request headers
      Authorization = "Bearer {{secret:NAME}}"
    }

    approve = ["dashboard"]        # optional — gate on HITL approver names
                                   # ("dashboard" is always available;
                                   #  others are declared via approver blocks)

    swap {                         # optional, repeatable — body string substitution
      placeholder = "PLACEHOLDER"
      secret      = "{{secret:NAME}}"
    }

    mtls {                         # optional — present a client cert upstream
      ca   = "/etc/clawpatrol/k8s-ca.pem"
      cert = "/etc/clawpatrol/k8s-client.crt"
      key  = "/etc/clawpatrol/k8s-client.key"
    }

    match {                        # optional — per-request predicate
      # --- HTTP ---
      method        = ["POST", "DELETE"]
      path          = "/v1/messages"          # exact or glob (e.g. "/api/*")
      query         = { foo = ["bar"] }       # query[k] is list of allowed values
      headers       = { "X-Trace" = "yes" }
      body_json     = { "model" = "gpt-4o" }  # exact-shape JSON path → value
      body_contains = "DROP TABLE"            # cheap substring fallback

      # --- Kubernetes (only when host is a kube apiserver) ---
      # Globs supported. Prefix value with "!" to negate.
      verb      = ["create", "delete"]        # get|list|watch|create|update|patch|delete|<subresource>
      resource  = ["secrets", "pods/exec"]
      namespace = ["prod-*", "!kube-system"]
      name      = ["root-*"]
      params    = { stdin = "true" }          # arbitrary kube query params

      # --- SQL (postgres MITM) ---
      sql_verb        = ["DROP", "TRUNCATE"]   # SELECT|INSERT|UPDATE|DELETE|DROP|...
      tables          = ["secrets", "audit.*"] # qualified or globbed
      function        = ["pg_sleep"]
      statement       = "..."                  # exact statement text match
      statement_regex = "^DROP\\s+TABLE"       # Go regexp
      account         = "service-readonly"     # postgres user (rolname)
    }
  }

Profile / approver / integration / ruleset blocks live in the global
gateway config — DO NOT emit them. Only ` + "`rule`" + ` blocks here.

Rules evaluate top-down; first match wins. Device-scoped rules take
precedence over the same host's global rules.

Output rules — read carefully:
- Output ONLY HCL — no prose, no markdown fences.
- Preserve every existing rule UNLESS the user explicitly asks to
  remove or change it.
- For "deny X on Y", add a deny rule with the right match clause
  BEFORE any catch-all rule for that host.
- For "ask before X" / "approve X" / "prompt before X", set
  ` + "`approve = [\"dashboard\"]`" + ` (or another declared approver) on a
  matching rule — there is no "hitl" action.
- Use the EXACT attribute / block names above. No legacy YAML keys.
- If you cannot satisfy the request, return the original HCL unchanged.`

func generateRuleHCL(ctx context.Context, reg *OAuthRegistry, agent, owner, prompt, currentHCL, scope string) (string, error) {
	if agent == "" {
		// pick whichever is connected
		for _, id := range []string{"claude", "codex"} {
			if owners := reg.Owners(id); len(owners) > 0 {
				for _, o := range owners {
					if o == owner {
						agent = id
						break
					}
				}
			}
			if agent != "" {
				break
			}
		}
	}
	if agent == "" {
		return "", fmt.Errorf("no connected LLM provider — connect Claude or Codex first")
	}
	user := fmt.Sprintf("Current %s rules HCL:\n\n%s\n\nApply this change:\n\n%s",
		scopeLabel(scope), currentHCL, prompt)
	switch agent {
	case "claude":
		return callClaude(ctx, reg, owner, user)
	case "codex":
		return callCodex(ctx, reg, owner, user)
	}
	return "", fmt.Errorf("unknown agent: %s", agent)
}

func scopeLabel(s string) string {
	if s == "device" {
		return "device-specific"
	}
	return "global"
}

// callClaude hits Anthropic's /v1/messages with the rule system prompt.
// Uses the operator's OAuth credential — Inject() adds the Authorization
// header to a freshly-built request.
func callClaude(ctx context.Context, reg *OAuthRegistry, owner, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":      "claude-haiku-4-5",
		"max_tokens": 4096,
		"system":     ruleSystemPrompt,
		"messages": []map[string]any{
			{"role": "user", "content": user},
		},
	})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	if _, err := reg.Inject("claude", owner, req); err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("anthropic %d: %s", resp.StatusCode, truncate(string(rb), 400))
	}
	var msg struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(rb, &msg); err != nil {
		return "", err
	}
	for _, c := range msg.Content {
		if c.Type == "text" && c.Text != "" {
			return cleanCodeFences(c.Text), nil
		}
	}
	return "", fmt.Errorf("anthropic: no text content in response")
}

// callCodex routes through the OpenAI Responses API. Mirrors callClaude
// for the Codex OAuth integration. Uses gpt-5-mini (fast, cheap) for
// rule generation.
func callCodex(ctx context.Context, reg *OAuthRegistry, owner, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model": "gpt-5-mini",
		"input": []map[string]any{
			{"role": "system", "content": []map[string]any{{"type": "input_text", "text": ruleSystemPrompt}}},
			{"role": "user", "content": []map[string]any{{"type": "input_text", "text": user}}},
		},
	})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.openai.com/v1/responses", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if _, err := reg.Inject("codex", owner, req); err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("openai %d: %s", resp.StatusCode, truncate(string(rb), 400))
	}
	var r struct {
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(rb, &r); err != nil {
		return "", err
	}
	for _, o := range r.Output {
		for _, c := range o.Content {
			if c.Text != "" {
				return cleanCodeFences(c.Text), nil
			}
		}
	}
	return "", fmt.Errorf("openai: no text content in response")
}

// cleanCodeFences strips ```hcl / ```yaml / ``` markdown fences if the
// model included them despite instructions.
func cleanCodeFences(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"```hcl", "```HCL", "```yaml", "```YAML", "```"} {
		if strings.HasPrefix(s, p) {
			s = strings.TrimPrefix(s, p)
			break
		}
	}
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}
