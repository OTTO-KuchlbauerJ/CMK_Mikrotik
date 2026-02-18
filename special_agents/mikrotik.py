#!/usr/bin/env python3
from cmk.special_agents.v1 import (
    SpecialAgentConfiguration,
    special_agent_configuration,
)
import shlex

def quote_shell_string(s: str) -> str:
    return shlex.quote(s)

@special_agent_configuration
def agent_mikrotik(params: dict, hostname: str, ipaddress: str) -> SpecialAgentConfiguration:
    args = []
    
    # Required parameters
    args += ["--user", quote_shell_string(params["user"])]
    args += ["--pass", quote_shell_string(params["password"])]
    
    # Optional parameters
    if params.get("no-ssl", False):
        args.append("--no-ssl")
    elif params.get("skip-cert-check", False):
        args.append("--skip-cert-check")
    
    if params.get("rest", False):
        args.append("--rest")
    
    args += ["--connect", str(params.get("connect", 8729))]
    args += ["--modules", ",".join(params["infos"])]
    args.append(quote_shell_string(ipaddress))
    
    return SpecialAgentConfiguration(args, timeout_seconds=30)