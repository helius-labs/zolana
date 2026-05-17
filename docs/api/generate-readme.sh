#!/usr/bin/env bash
# Generates docs/api/README.md from docs/api/openapi.yaml.
# Requires: python3 + PyYAML (pip install pyyaml)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SPEC="$SCRIPT_DIR/openapi.yaml"
OUTPUT="$SCRIPT_DIR/README.md"

python3 -c "
import yaml, sys

with open('$SPEC') as f:
    spec = yaml.safe_load(f)

info = spec['info']
lines = []
lines.append(f\"# {info['title']}\")
lines.append('')
lines.append(info.get('description', '').strip())
lines.append('')

tagged = {}
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        if method in ('get', 'post', 'put', 'delete', 'patch'):
            tags = details.get('tags', ['untagged'])
            for tag in tags:
                tagged.setdefault(tag, []).append((path, method, details))

def resolve_ref(ref):
    if ref and '\$ref' in ref:
        return ref['\$ref'].split('/')[-1]
    return None

def get_response_schema(details):
    resp = details.get('responses', {}).get('200', {})
    content = resp.get('content', {}).get('application/json', {})
    schema = content.get('schema', {})
    ref = resolve_ref(schema)
    if ref:
        return ref
    t = schema.get('type', '')
    if t == 'array':
        items = schema.get('items', {})
        item_ref = resolve_ref(items)
        if item_ref:
            return f'{item_ref}[]'
    return t or 'void'

endpoint_num = 0
for tag in spec.get('tags', []):
    name = tag['name']
    desc = tag.get('description', '')
    endpoints = tagged.get(name, [])
    if not endpoints:
        continue

    lines.append(f'## {desc}')
    lines.append('')
    lines.append('| # | Endpoint | Description | Response |')
    lines.append('|---|----------|-------------|----------|')

    for path, method, details in endpoints:
        endpoint_num += 1
        summary = details.get('summary', '')
        full_desc = details.get('description', '').strip().replace('\n', ' ')
        display_desc = full_desc if full_desc else summary
        resp_schema = get_response_schema(details)
        lines.append(f'| {endpoint_num} | \`{path}\` | {display_desc} | \`{resp_schema}\` |')

    lines.append('')

schemas = spec.get('components', {}).get('schemas', {})
err_obj = schemas.get('BackendErrorObject') or schemas.get('ErrorObject')
if err_obj:
    code_props = err_obj.get('properties', {}).get('code', {})
    desc_text = code_props.get('description', '')
    error_rows = []
    for line in desc_text.split('\n'):
        line = line.strip()
        if line.startswith('- -320'):
            line = line[2:]
            code, _, name = line.partition(':')
            if name:
                error_rows.append((code.strip(), name.strip()))
    if error_rows:
        lines.append('## Error Codes')
        lines.append('')
        lines.append('Errors use the JSON-RPC error object:')
        lines.append('')
        lines.append('| Code | Error |')
        lines.append('|------|-------|')
        for code, name in error_rows:
            lines.append(f'| \`{code}\` | {name} |')
        lines.append('')

lines.append('---')
lines.append('*Auto-generated from \`openapi.yaml\`. Do not edit manually.*')
lines.append('*Regenerate with: \`./docs/api/generate-readme.sh\` or \`just gen-api-readme\`.*')

print('\n'.join(lines))
" > "$OUTPUT"

echo "Generated $OUTPUT"
