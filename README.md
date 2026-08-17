# aegis-llm-security-auditor
# 🛡️ Aegis-LLM: AI Agent & MCP Security Linter

A specialized security utility designed to defend LLM-powered applications and autonomous AI agents against **Prompt Injection (OWASP LLM01)**, **System Prompt Extraction**, and **Model Context Protocol (MCP) Over-Privileging**.

---

## ⚡ What It Does
- **Adversarial Prompt Defense**: Intercepts user inputs before they reach the model, flagging role-override directives and jailbreak attempts.
- **MCP Tool Privilege Auditing**: Scans `mcpServers` configuration files to identify high-risk tool definitions (like unconstrained shell execution or raw SQL access).
- **Configuration Credential Checks**: Identifies sensitive database credentials and API tokens stored in agent environment variables.
- **Zero Third-Party Dependencies**: Pure Python implementation.

---

## 🚀 Quick Start

### 1. Run the Security Scanner
```bash
python3 aegis_llm_auditor.py mcp_server_config.sample.json

2. Integration Example (Guardrail Middleware)
Python
from aegis_llm_auditor import AegisLLMAuditor

auditor = AegisLLMAuditor()
is_safe = auditor.audit_prompt(user_input)

if not is_safe:
    raise ValueError("Request blocked by Aegis-LLM Security Guardrail.")
