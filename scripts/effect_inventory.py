#!/usr/bin/env python3
"""Effect-site inventory for darm_guard: every call that can change the world,
the function it sits in, and every entry point from which that function is
reachable (backwards over the module's own call graph). Parses the code; does
not grep. Usage: python3 effect_inventory.py [package_dir]"""
import ast, collections, json, os, sys

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
PKG = ARGS[0] if ARGS else "darm_guard"
JSON = "--json" in sys.argv
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

def callee(node):
    f = node.func
    if isinstance(f, ast.Attribute):
        base = f.value.id if isinstance(f.value, ast.Name) else "?"
        return base, f.attr
    if isinstance(f, ast.Name):
        return "", f.id
    return "?", "?"

OS_EFFECTS = {"replace", "rename", "unlink", "remove", "setxattr", "removexattr", "mkdir",
              "makedirs", "rmdir", "truncate", "ftruncate", "link", "symlink", "chmod",
              "fchmod", "chown", "renames", "removedirs", "utime", "mknod", "mkfifo",
              "lchown", "lchmod", "system", "popen", "fork", "kill"}
SHUTIL_EFFECTS = {"move", "rmtree", "copy", "copy2", "copyfile", "copytree"}

FOREIGN = set()   # names bound to ctypes libraries in the module, filled per module

def _mode(node, pos):
    m = node.args[pos] if len(node.args) > pos else next(
        (k.value for k in node.keywords if k.arg == "mode"), None)
    return m.value if isinstance(m, ast.Constant) and isinstance(m.value, str) else None

def effect_of(node, src):
    base, name = callee(node)
    text = ast.get_source_segment(src, node) or ""
    if base == "os" and name in OS_EFFECTS:
        return f"os.{name}"
    if base == "shutil" and name in SHUTIL_EFFECTS:
        return f"shutil.{name}"
    if name == "renameat2":
        return "renameat2"
    if base == "subprocess":
        return f"subprocess.{name}"
    if base == "os" and (name.startswith("exec") or name.startswith("spawn")):
        return f"os.{name}"
    if base in FOREIGN:
        return f"foreign:{base}.{name}"
    if name in ("write_text", "write_bytes"):
        return name
    if base == "os" and name == "open" and any(fl in text for fl in WRITE_FLAGS):
        return "os.open(write)"
    if base == "" and name == "open":
        m = _mode(node, 1)
        if m and any(c in m for c in "wax+"):
            return f"open({m!r})"
    if base == "os" and name == "fdopen":
        m = _mode(node, 1)
        if m and any(c in m for c in "wax+"):
            return f"os.fdopen({m!r})"
    return None

class Walker(ast.NodeVisitor):
    def __init__(self, mod, src):
        self.mod, self.src, self.stack = mod, src, []
        self.calls = collections.defaultdict(set)   # function -> bare names it calls
        self.effects = []                             # (line, effect, function)
        self.defs = set()
    def visit_ClassDef(self, n):
        self.stack.append(n.name); self.generic_visit(n); self.stack.pop()
    def visit_FunctionDef(self, n):
        self.stack.append(n.name)
        self.defs.add(".".join(self.stack))
        self.generic_visit(n); self.stack.pop()
    visit_AsyncFunctionDef = visit_FunctionDef
    def visit_Call(self, n):
        fn = ".".join(self.stack) or "<module>"
        _, name = callee(n)
        self.calls[fn].add(name)
        e = effect_of(n, self.src)
        if e:
            self.effects.append((n.lineno, e, fn))
        self.generic_visit(n)

allcalls, alldefs, rows = collections.defaultdict(set), set(), []
for fname in sorted(os.listdir(PKG)):
    if not fname.endswith(".py"):
        continue
    path = os.path.join(PKG, fname); src = open(path).read()
    tree = ast.parse(src)
    FOREIGN.clear()
    for a in ast.walk(tree):   # any name bound to ctypes.CDLL(...) or similar is a foreign library
        if isinstance(a, ast.Assign) and isinstance(a.value, ast.Call):
            seg = ast.get_source_segment(src, a.value) or ""
            if "CDLL" in seg or "LibraryLoader" in seg or "ctypes.cdll" in seg:
                for tg in a.targets:
                    if isinstance(tg, ast.Name):
                        FOREIGN.add(tg.id)
                    elif isinstance(tg, ast.Attribute):
                        FOREIGN.add(tg.attr)
    w = Walker(fname, src); w.visit(tree)
    for f, c in w.calls.items():
        allcalls[f"{fname}:{f}"] |= c
    alldefs |= {f"{fname}:{d}" for d in w.defs}
    rows += [(fname, line, eff, f"{fname}:{fn}") for line, eff, fn in w.effects]

def short(q): return q.split(":", 1)[1].split(".")[-1]
callers = collections.defaultdict(set)
for f, names in allcalls.items():
    for d in alldefs:
        if short(d) in names and d != f:
            callers[d].add(f)

def roots(fn):
    seen, todo, out = {fn}, [fn], set()
    while todo:
        x = todo.pop()
        cs = callers.get(x, set())
        if not cs:
            out.add(x)
        for c in cs:
            if c not in seen:
                seen.add(c); todo.append(c)
    return sorted(out)

if JSON:
    print(json.dumps([{"module": m, "function": fn.split(":", 1)[1], "effect": e}
                      for m, _l, e, fn in sorted(rows)]))
    sys.exit(0)
print(f"{'site':28} {'effect':22} {'in function':38} reached from")
for mod, line, eff, fn in sorted(rows):
    r = roots(fn)
    print(f"{mod}:{line:<20} {eff:22} {fn.split(':',1)[1]:38} {', '.join(x.split(':',1)[1] for x in r)}")
print(f"\n{len(rows)} effect sites in {len({r[3] for r in rows})} functions")
