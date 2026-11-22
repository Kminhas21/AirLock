import type { ChildProcess } from "node:child_process";

// Forward a spawned agent's stderr (agent_cli and, through it, the proxy, the sandbox trampoline and the downstream server) to the test output,
// one prefixed line at a time, so a CI failure shows why a call never reached the hub. Buffered by line (a chunk may end mid-line) and decoded
// as UTF-8 by the stream (a chunk may end mid-character). Reading the pipe also keeps a chatty child from blocking on a full one.
export function forwardStderr(p: ChildProcess, label: string): void {
  if (!p.stderr) return;
  let partial = "";
  const emit = (line: string) => { if (line.trim()) process.stderr.write(`[${label}] ${line}\n`); };
  p.stderr.setEncoding("utf8");
  p.stderr.on("data", (chunk: string) => {
    const lines = (partial + chunk).split("\n");
    partial = lines.pop() ?? "";
    lines.forEach(emit);
  });
  p.stderr.on("end", () => { emit(partial); partial = ""; });
}
