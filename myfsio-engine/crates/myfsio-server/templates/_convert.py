import os
import re
import sys

TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))

TERNARY_RE = re.compile(
    r"""(\{\{\s*)
        (?:"([^"]*)"|'([^']*)')      # literal A
        \s+if\s+
        ([^{}]+?)                    # condition
        \s+else\s+
        (?:"([^"]*)"|'([^']*)')      # literal B
        (\s*\}\})""",
    re.VERBOSE,
)

TERNARY_SET_RE = re.compile(
    r"""(\{%\s*set\s+([A-Za-z_][A-Za-z_0-9]*)\s*=\s*)
        (?:"([^"]*)"|'([^']*)')
        \s+if\s+
        ([^{}]+?)
        \s+else\s+
        (?:"([^"]*)"|'([^']*)')
        (\s*%\})""",
    re.VERBOSE,
)


def convert_single_quoted_strings_in_expressions(text: str) -> str:
    """Inside {{...}} or {%...%}, swap ' for " around tokens that look like strings."""
    def fix(m):
        body = m.group(2)
        body_fixed = re.sub(r"'([^'\\\n]*)'", r'"\1"', body)
        return m.group(1) + body_fixed + m.group(3)

    return re.sub(
        r"(\{[{%])([^{}]*?)([}%]\})",
        fix,
        text,
        flags=re.DOTALL,
    )


def convert_inline_ternary(text: str) -> str:
    def repl_expr(m):
        a = m.group(2) if m.group(2) is not None else m.group(3)
        cond = m.group(4)
        b = m.group(5) if m.group(5) is not None else m.group(6)
        return (
            '{% if ' + cond + ' %}' + a + '{% else %}' + b + '{% endif %}'
        )

    def repl_set(m):
        varname = m.group(2)
        a = m.group(3) if m.group(3) is not None else m.group(4)
        cond = m.group(5)
        b = m.group(6) if m.group(6) is not None else m.group(7)
        return (
            '{% if ' + cond + ' %}{% set ' + varname + ' = "' + a + '" %}'
            '{% else %}{% set ' + varname + ' = "' + b + '" %}{% endif %}'
        )

    prev = None
    while prev != text:
        prev = text
        text = TERNARY_SET_RE.sub(repl_set, text)
        text = TERNARY_RE.sub(repl_expr, text)
    return text


def convert_request_args(text: str) -> str:
    text = re.sub(
        r'request\.args\.get\(\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\)',
        r'request_args.\1 | default(value="\2")',
        text,
    )
    text = re.sub(
        r'request\.args\.get\(\s*"([^"]+)"\s*\)',
        r'request_args.\1',
        text,
    )
    text = text.replace('request.endpoint', 'current_endpoint')
    return text


def convert_items_keys(text: str) -> str:
    text = re.sub(r'\.items\(\)', '', text)
    text = re.sub(r'\.keys\(\)', '', text)
    text = re.sub(r'\.values\(\)', '', text)
    return text


def convert_tojson(text: str) -> str:
    text = re.sub(r'\|\s*tojson\b', '| json_encode | safe', text)
    return text


def convert_is_none(text: str) -> str:
    text = re.sub(r'\bis\s+not\s+none\b', '!= null', text)
    text = re.sub(r'\bis\s+none\b', '== null', text)
    return text


def convert_namespace(text: str) -> str:
    def repl(m):
        body = m.group(1)
        assigns = [a.strip() for a in body.split(',')]
        return '{# namespace shim #}'

    text = re.sub(
        r'\{%\s*set\s+ns\s*=\s*namespace\(([^)]*)\)\s*%\}',
        repl,
        text,
    )
    text = re.sub(r'\bns\.([A-Za-z_][A-Za-z_0-9]*)\s*=\s*', r'{% set_global \1 = ', text)
    text = re.sub(r'\bns\.([A-Za-z_][A-Za-z_0-9]*)', r'\1', text)
    return text


def convert_url_for_positional(text: str) -> str:
    """url_for("x", ...) -> url_for(endpoint="x", ...)"""
    def repl(m):
        prefix = m.group(1)
        endpoint = m.group(2)
        rest = m.group(3) or ''
        rest = rest.strip()
        if rest.startswith(','):
            rest = rest[1:].strip()
        if rest:
            return f'{prefix}(endpoint="{endpoint}", {rest})'
        return f'{prefix}(endpoint="{endpoint}")'

    pattern = re.compile(r'(url_for)\(\s*"([^"]+)"\s*((?:,[^()]*)?)\)')
    prev = None
    while prev != text:
        prev = text
        text = pattern.sub(repl, text)
    return text


def convert_d_filter(text: str) -> str:
    text = re.sub(r'\|\s*d\(\s*([^)]*?)\s*\)', lambda m: f'| default(value={m.group(1) or 0})', text)
    return text


def convert_replace_filter(text: str) -> str:
    def repl(m):
        a = m.group(1)
        b = m.group(2)
        return f'| replace(from="{a}", to="{b}")'
    text = re.sub(r'\|\s*replace\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)', repl, text)
    return text


def convert_truncate_filter(text: str) -> str:
    def repl(m):
        n = m.group(1)
        return f'| truncate(length={n})'
    text = re.sub(r'\|\s*truncate\(\s*(\d+)\s*(?:,[^)]*)?\)', repl, text)
    return text


def convert_strip_method(text: str) -> str:
    text = re.sub(r'(\b[A-Za-z_][A-Za-z_0-9.\[\]"]*)\s*\.\s*strip\(\s*\)', r'\1 | trim', text)
    return text


def convert_split_method(text: str) -> str:
    def repl(m):
        obj = m.group(1)
        sep = m.group(2)
        return f'{obj} | split(pat="{sep}")'
    text = re.sub(r'(\b[A-Za-z_][A-Za-z_0-9.]*)\s*\.\s*split\(\s*"([^"]*)"\s*\)', repl, text)
    return text


def convert_python_slice(text: str) -> str:
    def repl_colon(m):
        obj = m.group(1)
        start = m.group(2) or '0'
        end = m.group(3)
        if start.startswith('-') or (end and end.startswith('-')):
            return m.group(0)
        if end:
            return f'{obj} | slice(start={start}, end={end})'
        return f'{obj} | slice(start={start})'

    def repl_neg_end(m):
        obj = m.group(1)
        n = m.group(2)
        return f'{obj} | slice(start=-{n})'

    text = re.sub(
        r'(\b[A-Za-z_][A-Za-z_0-9.]*)\[\s*(-?\d*)\s*:\s*(-?\d*)\s*\]',
        repl_colon,
        text,
    )
    text = re.sub(
        r'(\b[A-Za-z_][A-Za-z_0-9.]*)\|\s*slice\(start=-(\d+)\s*,\s*end=\s*\)',
        repl_neg_end,
        text,
    )
    return text


def convert_inline_ternary_expr(text: str) -> str:
    """Handle arbitrary ternary inside {{ ... }}: A if COND else B -> {% if COND %}A{% else %}B{% endif %}"""
    out_lines = []
    for line in text.split('\n'):
        out_lines.append(_convert_line_ternary(line))
    return '\n'.join(out_lines)


def _convert_line_ternary(line: str) -> str:
    if '{{' not in line or ' if ' not in line or ' else ' not in line:
        return line
    prev = None
    while prev != line:
        prev = line
        m = re.search(r'\{\{\s*([^{}]+?)\s+if\s+([^{}]+?)\s+else\s+([^{}]+?)\s*\}\}', line)
        if not m:
            break
        replacement = '{% if ' + m.group(2) + ' %}{{ ' + m.group(1) + ' }}{% else %}{{ ' + m.group(3) + ' }}{% endif %}'
        line = line[:m.start()] + replacement + line[m.end():]
    return line


def convert_dict_get(text: str) -> str:
    """Convert X.get("key", default) -> X.key | default(value=default) when simple."""
    pattern = re.compile(
        r'([A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*)'
        r'\.get\(\s*"([A-Za-z_][A-Za-z_0-9]*)"\s*(?:,\s*([^(){}]+?))?\s*\)'
    )

    def repl(m):
        obj = m.group(1)
        key = m.group(2)
        default = (m.group(3) or '').strip()
        if default:
            return f'{obj}.{key} | default(value={default})'
        return f'{obj}.{key}'

    prev = None
    while prev != text:
        prev = text
        text = pattern.sub(repl, text)
    return text


def convert_file(path: str) -> bool:
    with open(path, 'r', encoding='utf-8') as f:
        original = f.read()
    text = original
    text = convert_single_quoted_strings_in_expressions(text)
    text = convert_inline_ternary(text)
    text = convert_request_args(text)
    text = convert_items_keys(text)
    text = convert_tojson(text)
    text = convert_is_none(text)
    text = convert_namespace(text)
    text = convert_dict_get(text)
    text = convert_url_for_positional(text)
    text = convert_d_filter(text)
    text = convert_replace_filter(text)
    text = convert_truncate_filter(text)
    text = convert_strip_method(text)
    text = convert_split_method(text)
    text = convert_python_slice(text)
    text = convert_inline_ternary_expr(text)
    if text != original:
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
        return True
    return False


def main():
    changed = []
    for name in sorted(os.listdir(TEMPLATE_DIR)):
        if not name.endswith('.html'):
            continue
        p = os.path.join(TEMPLATE_DIR, name)
        if convert_file(p):
            changed.append(name)
    print('Changed:', len(changed))
    for c in changed:
        print(' -', c)


if __name__ == '__main__':
    main()
