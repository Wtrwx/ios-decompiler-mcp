"""Build the injected bundle using the official compiler in frida-python."""

from pathlib import Path

import frida

root = Path(__file__).resolve().parents[1]
compiler = frida.Compiler()
compiler.on("diagnostics", lambda diagnostics: print(diagnostics))
source = compiler.build(str(root / "agents/frida/index.ts"), project_root=str(root), source_maps="omitted")
output = root / "src/vesper/assets/agent.js"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(source)
print(f"Built {output.relative_to(root)} ({len(source)} characters)")
