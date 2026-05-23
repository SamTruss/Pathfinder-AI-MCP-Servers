# Pathfinder AI — MCP Servers

Public [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers for the **Pathfinder AI** agentic VAPT framework — modular tool integrations for IIoT/OT/SCADA security assessment.

## Overview

Pathfinder AI is an MCP-based agentic VAPT framework integrating LLMs, generative AI, and reinforcement learning for autonomous vulnerability assessment and penetration testing in IIoT/OT/SCADA environments. It is evaluated against NIST CSF and ISO 27001, with an empirical core built on a SWaT-inspired Modbus testbed.

This repository houses the **public MCP server implementations** that provide Pathfinder AI's tool layer — the modular, protocol-compliant interfaces between the agentic reasoning engine and the underlying security tooling.

## Repository Structure

```
pathfinder-mcp-servers/
├── servers/              # Individual MCP server implementations
│   ├── <server-name>/    # Each server in its own directory
│   │   ├── README.md     # Server-specific documentation
│   │   ├── server.py     # MCP server entry point
├── SECURITY.md           # Security policy and vulnerability reporting
├── CODE_OF_CONDUCT.md    # Contributor code of conduct
├── CHANGELOG.md          # Version history
├── LICENSE               # MIT License
└── README.md             # This file
```

## MCP Server Catalogue

| Server | Description | Status |
|--------|-------------|--------|
| *Coming soon* | Initial servers under development | 🔧 In Progress |

> Servers will be added here as they are developed and stabilised.

## Getting Started

### Prerequisites

- Python 3.11+
- [MCP SDK](https://github.com/modelcontextprotocol/python-sdk)
- Server-specific dependencies (see individual server READMEs)

### Installation

```bash
# Clone the repository
git clone https://github.com/SamTruss/Pathfinder-AI-MCP-Servers.git
cd Pathfinder-AI-MCP-Servers

# Install a specific server
cd servers/<server-name>
pip install -r requirements.txt
```

### Running a Server

Each server can be run independently:

```bash
python servers/<server-name>/server.py
```

Or referenced via MCP configuration:

```json
{
  "mcpServers": {
    "<server-name>": {
      "command": "python",
      "args": ["servers/<server-name>/server.py"]
    }
  }
}
```

## Integration with Pathfinder AI

These servers are consumed by the [Pathfinder AI](https://github.com/SamTruss/Pathfinder-AI) framework as its tool layer. In the Pathfinder AI architecture, MCP servers sit at **Layer 2 (Tool Orchestration)** of the four-layer Agentic–Generative VAPT model.

This repository is linked as a Git submodule within the private Pathfinder AI repository, enabling independent versioning and public collaboration on the tool layer without exposing the core agentic reasoning engine.

## Research Context

This work forms part of an ongoing PhD at Keele University investigating agentic and generative AI for autonomous VAPT in OT environments.

**Related publication:**
> Sherwood, S., Ghanem, M. C., & Lacerda, M. J. — *Agentic and Generative AI for Autonomous VAPT: A Systematic Analysis*. Submitted to Information and Software Technology.

**Publicly archived:** [OSF — osf.io/d7p8j](https://osf.io/d7p8j)

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Security

For security concerns and vulnerability reporting, see [SECURITY.md](SECURITY.md).
