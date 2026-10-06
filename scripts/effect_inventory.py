#!/usr/bin/env python3
"""Effect-site inventory for darm_guard (v3).

Every call that can change the world, resolved through import aliases
(import os as x; from os import unlink as y), and every reference to an effect
function that is not a direct call (bound to a name, passed along, or reached
through getattr on a module): those are sites too, and must be classified.
For each function, a fingerprint of its typed tokens (comments and indentation
width ignored, but suite boundaries and logical newlines retained); for each effect function, every
function from which it can be reached, each with its fingerprint, so a verdict
is bound to the code it was reviewed against. v3: a verdict's cone runs in both directions: every function
on a route into the effect function (calls and references, such as a thread
target), every function those call, transitively, and the module-level code of
every module involved; eval, exec, compile, __import__ and importlib are sites.
Usage: effect_inventory.py [package_dir] [--json]"""
import ast, collections, hashlib, io, json, os, sys, textwrap, tokenize

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
PKG = ARGS[0] if ARGS else "darm_guard"
JSON = "--json" in sys.argv

OS_EFFECTS = {"replace", "rename", "unlink", "remove", "setxattr", "removexattr", "mkdir",
              "makedirs", "rmdir", "truncate", "ftruncate", "link", "symlink", "chmod",
              "fchmod", "chown", "renames", "removedirs", "utime", "mknod", "mkfifo",
              "lchown", "lchmod", "system", "popen", "fork", "kill"}
SHUTIL_EFFECTS = {"move", "rmtree", "copy", "copy2", "copyfile", "copytree"}
SUBPROCESS_EFFECTS = {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}
# network: anything that opens a connection or a socket (v4)
NET_EFFECTS = {"socket": {"socket", "create_connection", "create_server", "socketpair", "fromfd"},
               "http.client": {"HTTPConnection", "HTTPSConnection"},
               "urllib.request": {"urlopen", "urlretrieve", "build_opener"}}
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
MODULES = {"os", "shutil", "subprocess"} | set(NET_EFFECTS)
DYNAMIC = {"eval", "exec", "compile", "__import__"}
SKIP = {tokenize.COMMENT, tokenize.NL, tokenize.ENCODING, tokenize.ENDMARKER}
STRUCTURE = {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}

def token_fp(text):
    # Indentation is executable structure in Python. Normalize its width, not
    # its presence. Token types also distinguish structural markers from text.
    toks = [(tokenize.tok_name[t.type], "" if t.type in STRUCTURE else t.string)
            for t in tokenize.generate_tokens(io.StringIO(textwrap.dedent(text)).readline)
            if t.type not in SKIP]
    return hashlib.sha256(json.dumps(toks, separators=(",", ":")).encode()).hexdigest()

def is_effect(mod, name):
    return (mod == "os" and name in OS_EFFECTS) or (mod == "shutil" and name in SHUTIL_EFFECTS) \
        or (mod == "subprocess" and name in SUBPROCESS_EFFECTS) or name in NET_EFFECTS.get(mod, ())

def _dotted(e):
    """a.b.c for a chain of names, else None."""
    parts = []
    while isinstance(e, ast.Attribute):
        parts.append(e.attr); e = e.value
    if isinstance(e, ast.Name):
        return ".".join([e.id] + parts[::-1])
    return None

def _mode(node, pos):
    m = node.args[pos] if len(node.args) > pos else next(
        (k.value for k in node.keywords if k.arg == "mode"), None)
    return m.value if isinstance(m, ast.Constant) and isinstance(m.value, str) else None

class Walker(ast.NodeVisitor):
    def __init__(self, src, aliases, direct, foreign):
        self.src, self.lines = src, src.split("\n")
        self.aliases, self.direct, self.foreign = aliases, direct, foreign
        self.stack, self.calls = [], collections.defaultdict(set)
        self.effects, self.fps = [], {}
    def qual(self):
        return ".".join(self.stack) or "<module>"
    def modname(self, e):
        return self.aliases.get(e.id) if isinstance(e, ast.Name) else None
    def resolve(self, f):
        if isinstance(f, ast.Attribute):
            if isinstance(f.value, ast.Name):
                return self.aliases.get(f.value.id, f.value.id), f.attr
            dotted = _dotted(f.value)            # http.client.HTTPConnection, urllib.request.urlopen
            if dotted:
                return self.aliases.get(dotted, dotted), f.attr
            return "?", f.attr
        if isinstance(f, ast.Name):
            return self.direct.get(f.id, ("", f.id))
        return "?", "?"
    def effect_of(self, n, base, name):
        text = ast.get_source_segment(self.src, n) or ""
        if base in ("os", "shutil") and is_effect(base, name):
            return f"{base}.{name}"
        if base == "subprocess" and name in SUBPROCESS_EFFECTS:
            return f"subprocess.{name}"
        if base == "os" and (name.startswith("exec") or name.startswith("spawn")):
            return f"os.{name}"
        if name == "renameat2":
            return "renameat2"
        if base in NET_EFFECTS and name in NET_EFFECTS[base]:
            return f"{base}.{name}"
        if base in self.foreign:
            return f"foreign:{base}.{name}"
        if name in ("write_text", "write_bytes"):
            return name
        if base == "os" and name == "open" and any(fl in text for fl in WRITE_FLAGS):
            return "os.open(write)"
        if base == "" and name == "open":
            m = _mode(n, 1)
            if m and any(c in m for c in "wax+"):
                return f"open({m!r})"
        if base == "os" and name == "fdopen":
            m = _mode(n, 1)
            if m and any(c in m for c in "wax+"):
                return f"os.fdopen({m!r})"
        return None
    def visit_ClassDef(self, n):
        self.stack.append(n.name); self.generic_visit(n); self.stack.pop()
    def visit_FunctionDef(self, n):
        self.stack.append(n.name)
        self.fps[self.qual()] = token_fp("\n".join(self.lines[n.lineno - 1:n.end_lineno]))
        self.generic_visit(n); self.stack.pop()
    visit_AsyncFunctionDef = visit_FunctionDef
    def visit_Call(self, n):
        fn = self.qual()
        base, name = self.resolve(n.func)
        self.calls[fn].add(name)
        e = self.effect_of(n, base, name)
        if e:
            self.effects.append((n.lineno, e, fn))
        if base == "" and name in DYNAMIC:
            self.effects.append((n.lineno, f"dynamic:{name}", fn))
        if base == "importlib" or (base, name) == ("importlib", "import_module"):
            self.effects.append((n.lineno, f"dynamic:importlib.{name}", fn))
        if base == "" and name == "getattr" and n.args and self.modname(n.args[0]) in MODULES:
            self.effects.append((n.lineno, f"dynamic:getattr({self.modname(n.args[0])})", fn))
        n.func._darm_called = True
        self.generic_visit(n)
    def visit_Attribute(self, n):
        if not getattr(n, "_darm_called", False) and isinstance(n.ctx, ast.Load):
            self.calls[self.qual()].add(n.attr)          # a reference is a route (thread targets, callbacks)
        if not getattr(n, "_darm_called", False):
            b = self.modname(n.value)
            if b and is_effect(b, n.attr):
                self.effects.append((n.lineno, f"reference:{b}.{n.attr}", self.qual()))
        self.generic_visit(n)
    def visit_Name(self, n):
        if not getattr(n, "_darm_called", False) and isinstance(n.ctx, ast.Load):
            self.calls[self.qual()].add(n.id)            # a reference is a route (thread targets, callbacks)
        if not getattr(n, "_darm_called", False) and isinstance(n.ctx, ast.Load) and n.id in self.direct:
            m, a = self.direct[n.id]
            if is_effect(m, a):
                self.effects.append((n.lineno, f"reference:{m}.{a}", self.qual()))

allcalls, fps, rows = collections.defaultdict(set), {}, []
for fname in sorted(os.listdir(PKG)):
    if not fname.endswith(".py"):
        continue
    src = open(os.path.join(PKG, fname)).read()
    tree = ast.parse(src)
    aliases, direct, foreign = {}, {}, set()
    for a in ast.walk(tree):
        if isinstance(a, ast.Import):
            for al in a.names:
                if al.name in MODULES or al.name == "importlib":
                    aliases[al.asname or al.name] = al.name
        elif isinstance(a, ast.ImportFrom) and a.module in MODULES | {"importlib"}:
            for al in a.names:
                direct[al.asname or al.name] = (a.module, al.name)
        elif isinstance(a, ast.ImportFrom) and a.module and any(f"{a.module}.{al.name}" in MODULES for al in a.names):
            for al in a.names:                   # from urllib import request; from http import client
                if f"{a.module}.{al.name}" in MODULES:
                    aliases[al.asname or al.name] = f"{a.module}.{al.name}"
        elif isinstance(a, ast.Assign) and isinstance(a.value, ast.Call):
            seg = ast.get_source_segment(src, a.value) or ""
            if "CDLL" in seg or "LibraryLoader" in seg or "ctypes.cdll" in seg:
                for tg in a.targets:
                    if isinstance(tg, ast.Name):
                        foreign.add(tg.id)
                    elif isinstance(tg, ast.Attribute):
                        foreign.add(tg.attr)
    w = Walker(src, aliases, direct, foreign)
    w.visit(tree)
    top = [ast.get_source_segment(src, s) or "" for s in tree.body
           if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    w.fps["<module>"] = token_fp("\n".join(top))
    for f, c in w.calls.items():
        allcalls[f"{fname}:{f}"] |= c
    fps.update({f"{fname}:{q}": v for q, v in w.fps.items()})
    rows += [(fname, line, eff, f"{fname}:{fn}") for line, eff, fn in w.effects]

def short(q):
    return q.split(":", 1)[1].split(".")[-1]
callers = collections.defaultdict(set)
for f, names in allcalls.items():
    for d in fps:
        if d != f and short(d) in names:
            callers[d].add(f)

callees = collections.defaultdict(set)
for f, cs in callers.items():
    for c in cs:
        callees[c].add(f)

def closure(start, edges):
    seen, todo = set(start), list(start)
    while todo:
        for c in edges.get(todo.pop(), ()):
            if c not in seen:
                seen.add(c); todo.append(c)
    return seen

def cone(fn):
    """Everything fn's verdict depends on: routes into it, everything called along
    them (and by fn), and the module-level code of every module involved."""
    up = closure({fn}, callers)
    down = closure(up, callees)
    members = up | down
    members |= {m.split(":", 1)[0] + ":<module>" for m in members}
    members.discard(fn)
    return sorted(members)

effect_fns = sorted({r[3] for r in rows})
if JSON:
    print(json.dumps({
        "sites": [{"module": m, "function": fn.split(":", 1)[1], "effect": e} for m, _l, e, fn in sorted(rows)],
        "functions": {fn: {"fingerprint": fps.get(fn, "?"),
                           "cone": {a: fps.get(a, "?") for a in cone(fn)}} for fn in effect_fns}}))
    sys.exit(0)
print(f"{'site':28} {'effect':26} {'in function':38} reached from")
for mod, line, eff, fn in sorted(rows):
    print(f"{mod}:{line:<20} {eff:26} {fn.split(':', 1)[1]:38} cone of {len(cone(fn))}")
print(f"\n{len(rows)} effect sites in {len(effect_fns)} functions")
