from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class RedactionPattern:
    name: str
    label: str
    severity: str
    regex: Pattern[str]
    replacement: str
    description: str


# xtr4ng3: local-only patterns. Nothing leaves the machine.
DEFAULT_PATTERNS: list[RedactionPattern] = [
    RedactionPattern("email", "Email address", "medium", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<REDACTED_EMAIL>", "Personal or business email address."),
    RedactionPattern("ipv4", "IPv4 address", "low", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "<REDACTED_IP>", "IPv4 address."),
    RedactionPattern("windows_user_path", "Windows user path", "medium", re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\r\n\t]+"), r"C:\Users\<USER>", "Local Windows user path."),
    RedactionPattern("unix_home_path", "Unix home path", "medium", re.compile(r"(?i)(/home/[^/\s]+|/Users/[^/\s]+)"), "/home/<USER>", "Local Unix-like home path."),
    RedactionPattern("discord_webhook", "Discord webhook", "high", re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"), "<REDACTED_DISCORD_WEBHOOK>", "Discord webhook URL."),
    RedactionPattern("github_token", "GitHub token", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"), "<REDACTED_GITHUB_TOKEN>", "GitHub token-like value."),
    RedactionPattern("aws_access_key", "AWS access key", "critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<REDACTED_AWS_ACCESS_KEY>", "AWS access key ID."),
    RedactionPattern("slack_token", "Slack token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "<REDACTED_SLACK_TOKEN>", "Slack token-like value."),
    RedactionPattern("jwt", "JWT token", "high", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "<REDACTED_JWT>", "JSON Web Token."),
    RedactionPattern("bearer_token", "Bearer token", "high", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.=]{20,}"), "Bearer <REDACTED_TOKEN>", "Bearer authorization token."),
    RedactionPattern("private_key", "Private key block", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "<REDACTED_PRIVATE_KEY>", "Private key block."),
    RedactionPattern("password_assignment", "Password assignment", "high", re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{4,})"), r"\1=<REDACTED_PASSWORD>", "Password assigned in config/log/code."),
    RedactionPattern("secret_assignment", "Secret assignment", "high", re.compile(r"(?i)\b(secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|db[_-]?password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.=/+]{12,})"), r"\1=<REDACTED_SECRET>", "Secret or token assigned in a file."),
    RedactionPattern("database_url", "Database URL", "high", re.compile(r"(?i)\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s'\"<>]+"), "<REDACTED_DATABASE_URL>", "Database connection URL."),
    RedactionPattern("cookie_header", "Cookie header", "medium", re.compile(r"(?i)\b(cookie|set-cookie)\s*:\s*[^\r\n]+"), r"\1: <REDACTED_COOKIE>", "HTTP cookie header."),
    RedactionPattern("url_token_param", "URL token parameter", "high", re.compile(r"(?i)([?&](?:token|key|apikey|api_key|access_token|auth|secret)=)[^&\s]+"), r"\1<REDACTED>", "Sensitive URL query parameter."),
]

SAFE_EXTENSIONS = {
    ".txt", ".log", ".env", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config",
    ".md", ".csv", ".xml", ".html", ".htm", ".css", ".js", ".ts", ".py", ".php", ".java", ".kt",
    ".rs", ".go", ".cs", ".cpp", ".c", ".h", ".hpp", ".bat", ".cmd", ".ps1", ".sh", ".sql",
}
SKIP_DIR_NAMES = {".git", ".svn", ".hg", "__pycache__", "node_modules", "target", "build", "dist", ".venv", "venv"}
