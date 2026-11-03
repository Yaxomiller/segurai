"""Optional integrations with the tools agents are already built on.

    otel.py       emit OpenTelemetry spans      pip install 'segurai[otel]'
    langgraph.py  LangGraph nodes and ToolNode  pip install 'segurai[langgraph]'
    mcp.py        MCP clients and servers       pip install 'segurai[mcp]'

None of these are imported by ``import segurai``, so the core library stays
dependency-free. Import the one you need: ``from segurai.instrument import otel``.
"""
