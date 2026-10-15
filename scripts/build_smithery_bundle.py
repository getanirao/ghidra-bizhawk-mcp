"""Build the Smithery publish variant of the MCPB bundle.

The canonical MCPB manifest (mcpb/manifest.json) must conform to the MCPB
schema, which forbids inputSchema/outputSchema on tools and requires
string-only prompt arguments. Smithery's publish API requires the opposite:
MCP-style tool schemas and object-form prompt arguments. This script takes
the already-packed MCPB bundle and rewrites only its manifest.json with the
schema data from mcpb/tool-schemas.json, producing a bundle that satisfies
Smithery while keeping mcpb/manifest.json valid for mcpb pack.

Usage:
    python scripts/build_smithery_bundle.py [path/to/bundle.mcpb]
"""

import json
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SIDECAR = REPO_ROOT / "mcpb" / "tool-schemas.json"
DEFAULT_BUNDLE = REPO_ROOT / "dist" / "ghidra-bizhawk-mcp.mcpb"
DEFAULT_OUTPUT = REPO_ROOT / "dist" / "ghidra-bizhawk-mcp.smithery.mcpb"


def build(bundle_path: Path, output_path: Path) -> None:
    if not bundle_path.is_file():
        raise SystemExit(
            f"MCPB bundle not found: {bundle_path} (run scripts/build-mcpb.ps1 first)"
        )
    schemas = json.loads(SIDECAR.read_text(encoding="utf-8"))

    with zipfile.ZipFile(bundle_path) as zin:
        try:
            manifest = json.loads(zin.read("manifest.json").decode("utf-8"))
        except KeyError:
            raise SystemExit("manifest.json not found at bundle root")

        patched = 0
        for tool in manifest.get("tools", []):
            entry = schemas["tools"].get(tool.get("name"))
            if not entry:
                raise SystemExit(f"no schema in sidecar for tool {tool.get('name')!r}")
            for key, value in entry.items():
                if key not in tool:
                    tool[key] = value
                    patched += 1

        for prompt in manifest.get("prompts", []):
            args = schemas["prompt_arguments"].get(prompt.get("name"))
            if not args:
                raise SystemExit(
                    f"no argument specs in sidecar for prompt {prompt.get('name')!r}"
                )
            prompt["arguments"] = args

        manifest_bytes = json.dumps(
            manifest, indent=2, ensure_ascii=False
        ).encode("utf-8")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = (
                    manifest_bytes
                    if item.filename == "manifest.json"
                    else zin.read(item.filename)
                )
                zout.writestr(item, data)

    size = output_path.stat().st_size
    if size > 25 * 1024 * 1024:
        raise SystemExit(f"bundle exceeds Smithery's 25 MB limit: {size} bytes")
    print(
        f"Wrote {output_path} ({size} bytes; "
        f"{patched} schema fields injected across {len(manifest.get('tools', []))} tools)"
    )


if __name__ == "__main__":
    bundle = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BUNDLE
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT
    build(bundle.resolve(), output.resolve())
