"""Optional integrations with the tools agents are already built on.

    otel.py       emit OpenTelemetry spans      pip install 'warrant-provenance[otel]'
    langgraph.py  LangGraph nodes and ToolNode  pip install 'warrant-provenance[langgraph]'
    mcp.py        MCP clients and servers       pip install 'warrant-provenance[mcp]'

None of these are imported by ``import warrant``, so the core library stays
dependency-free. Import the one you need: ``from warrant.instrument import otel``.
"""
