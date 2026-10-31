#!/usr/bin/env python3
"""Official MCP SDK stdio server; authority is supplied by the host launcher."""
import os
from pathlib import Path
from typing import Any
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from boundary import BoundaryDenied, FileBoundary

boundary = FileBoundary(Path(os.environ['CLIM_MCP_POLICY']),Path(os.environ['CLIM_MCP_STATE_DIR']))
mcp = MCPServer('CLIM boundary pilot',instructions=(
    'Use clim_set_debug for the disposable configuration experiment. Host policy is authoritative. '
    'After a CLIM denial, report it and stop; do not switch tools.'))


@mcp.tool()
def clim_set_debug(path: str, debug: bool, operation_id: str) -> dict[str, Any]:
    """Set debug in an existing JSON config under independent CLIM host authority."""
    try:
        return boundary.set_debug(path,debug,operation_id)
    except BoundaryDenied as exc:
        raise ToolError(str(exc)) from exc


if __name__=='__main__':
    mcp.run(transport='stdio')
