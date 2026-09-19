from __future__ import annotations
from typing import Any, List
from ..guard import DARMGuard


def guard_tools(tools: List[Any], guard: DARMGuard) -> List[Any]:
    wrapped = []
    for tool in tools:
        wrapped.append(_GuardedTool(tool, guard))
    return wrapped


class _GuardedTool:
    def __init__(self, tool: Any, guard: DARMGuard):
        self._tool = tool
        self._guard = guard
        self.name = getattr(tool, "name", str(tool))
        self.description = getattr(tool, "description", "")

    def run(self, *args: Any, **kwargs: Any) -> Any:
        result = self._guard.check({self.name})
        if not result:
            raise PermissionError(result.explain())
        return self._tool.run(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tool, name)
