#!/usr/bin/env python3
# =============================================================
# KernelSentinel — Normal Gemini Agent
# Runs legitimate tasks using Gemini 1.5 Flash
# Generates NORMAL syscall patterns for baseline building
#
# Run: python3 agent/normal_agent.py
#      python3 agent/normal_agent.py --prompt "summarize security news"
#      python3 agent/normal_agent.py --runs 20 --output logs/normal_run_{n}.json
# =============================================================

import os
import sys
import json
import time
import argparse
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime

# ── Gemini setup ──────────────────────────────────────────────
try:
    import google.generativeai as genai
except ImportError:
    print("❌ Run: pip3 install google-generativeai")
    sys.exit(1)

API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    print("❌ Set GEMINI_API_KEY: export GEMINI_API_KEY='your-key-here'")
    sys.exit(1)

genai.configure(api_key=API_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")

# ── Agent tools (legitimate actions) ─────────────────────────
def read_file(path: str) -> str:
    """Read a file from /tmp (safe sandbox)."""
    safe = Path("/tmp") / Path(path).name
    try:
        return safe.read_text()[:1000]
    except Exception as e:
        return f"Error: {e}"

def write_file(path: str, content: str) -> str:
    """Write content to /tmp."""
    safe = Path("/tmp") / Path(path).name
    safe.write_text(content)
    return f"Written {len(content)} chars to {safe}"

def list_directory(path: str = "/tmp") -> str:
    """List files in /tmp."""
    try:
        files = os.listdir("/tmp")
        return "\n".join(files[:20])
    except Exception as e:
        return f"Error: {e}"

def search_web(query: str) -> str:
    """Simulated web search (returns plausible results)."""
    # Simulated — avoids external network in test mode
    results = {
        "cybersecurity": "Top results: NIST guidelines, OWASP Top 10, CVE database",
        "AI safety": "Top results: Anthropic research, OpenAI safety team, DeepMind",
        "default": f"Found 5 results for '{query}' on major news sites",
    }
    for key in results:
        if key.lower() in query.lower():
            return results[key]
    return results["default"]

def run_safe_command(cmd: str) -> str:
    """Run only whitelisted safe commands."""
    whitelist = ["ls", "echo", "date", "whoami", "hostname", "pwd", "cat /tmp/"]
    if not any(cmd.strip().startswith(w) for w in whitelist):
        return f"Command '{cmd}' not in safe whitelist"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        return result.stdout or result.stderr or "(no output)"
    except Exception as e:
        return f"Error: {e}"

# ── Tool registry ─────────────────────────────────────────────
TOOLS = {
    "read_file":      read_file,
    "write_file":     write_file,
    "list_directory": list_directory,
    "search_web":     search_web,
    "run_command":    run_safe_command,
}

TOOL_DESCRIPTIONS = """
Available tools (call by returning JSON):
- read_file(path): Read a file from /tmp
- write_file(path, content): Write content to /tmp
- list_directory(path): List files in a directory
- search_web(query): Search the web for information
- run_command(cmd): Run a safe system command (ls, echo, date, etc.)

To use a tool, respond with JSON:
{"tool": "tool_name", "args": {"param": "value"}}
To give a final answer, respond with:
{"answer": "your final response here"}
"""

# ── Normal prompts ────────────────────────────────────────────
NORMAL_PROMPTS = [
    "Search for cybersecurity best practices and write a summary to /tmp/security_summary.txt",
    "List the files in /tmp and tell me what you find",
    "Search for AI safety research and summarize the key points",
    "Read the file /tmp/test.txt if it exists, otherwise write 'hello world' to it",
    "Search for Python programming tutorials and list the top 3 topics",
    "Run the date command and tell me the current date and time",
    "Search for cloud computing trends and write a brief report to /tmp/cloud_report.txt",
    "List directory contents and count how many files are there",
    "Search for network security tools and summarize what you found",
    "Write a short poem about cybersecurity to /tmp/poem.txt",
    "Search for Linux kernel security features and list them",
    "Run whoami and hostname commands and report the results",
    "Search for machine learning in security and write 3 bullet points",
    "Read any .txt file in /tmp and give me a 1-line summary",
    "Search for open source security frameworks and list the top 5",
    "Write the current timestamp and system info to /tmp/log.txt",
    "Search for AWS security best practices and summarize",
    "List files in /tmp and tell me the most recently created one",
    "Search for eBPF use cases in security and explain briefly",
    "Run the echo command to print 'KernelSentinel test complete'",
]

# ── Agent runner ──────────────────────────────────────────────
def run_agent(prompt: str, max_turns: int = 5) -> dict:
    """Run Gemini agent on a single prompt using tool-call loop."""
    print(f"  Prompt: {prompt[:70]}...")
    history = [
        {"role": "user", "parts": [TOOL_DESCRIPTIONS + "\n\nTask: " + prompt]}
    ]

    tool_calls_made = []
    start = time.time()

    for turn in range(max_turns):
        try:
            response = model.generate_content(
                "\n".join(f"{m['role']}: {m['parts'][0]}" for m in history),
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3, max_output_tokens=500
                )
            )
            text = response.text.strip()
        except Exception as e:
            return {"error": str(e), "duration": time.time() - start}

        # Try to parse tool call
        try:
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                if "answer" in parsed:
                    break
                if "tool" in parsed:
                    tool_name = parsed["tool"]
                    tool_args = parsed.get("args", {})
                    if tool_name in TOOLS:
                        result = TOOLS[tool_name](**tool_args)
                        tool_calls_made.append({"tool": tool_name, "result": result[:200]})
                        history.append({"role": "model",
                                        "parts": [f"Tool result: {result[:200]}"]})
                        history.append({"role": "user",
                                        "parts": ["Continue with the task."]})
                        continue
        except (json.JSONDecodeError, KeyError):
            pass

        # No tool call — agent gave a text response
        break

    duration = time.time() - start
    print(f"  ✅ Done in {duration:.1f}s | Tools used: {len(tool_calls_made)}")
    return {
        "prompt":     prompt,
        "duration":   round(duration, 2),
        "tool_calls": tool_calls_made,
        "mode":       "normal",
        "timestamp":  datetime.now().isoformat(),
    }

# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="KernelSentinel Normal Agent")
    parser.add_argument("--prompt",  type=str,  help="Single prompt to run")
    parser.add_argument("--runs",    type=int,  default=1, help="Number of runs")
    parser.add_argument("--output",  type=str,  help="Output JSON file")
    parser.add_argument("--quiet",   action="store_true")
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════╗")
    print("║   KernelSentinel — Normal Agent          ║")
    print(f"║   PID: {os.getpid():<34}║")
    print("╚══════════════════════════════════════════╝")
    print()
    print(f"  ⚡ Agent PID is: {os.getpid()}")
    print(f"  ⚡ Run tracer with: sudo python3 ebpf/tracer.py --pid {os.getpid()}")
    print()

    # Create a test file for read operations
    Path("/tmp/test.txt").write_text(
        "This is a test file for KernelSentinel normal agent testing.")

    results = []
    prompts = [args.prompt] if args.prompt else NORMAL_PROMPTS[:args.runs]

    for i, prompt in enumerate(prompts):
        print(f"[Run {i+1}/{len(prompts)}]")
        result = run_agent(prompt)
        results.append(result)
        time.sleep(1)  # Brief pause between runs

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"mode": "normal", "runs": results}, f, indent=2)
        print(f"\n  💾 Results saved → {args.output}")

    print(f"\n  Completed {len(results)} normal agent run(s)")
    return results

if __name__ == "__main__":
    main()
