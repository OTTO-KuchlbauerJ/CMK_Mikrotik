#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    State,
    StringTable,
)
from typing import Dict, Any

def parse_mikrotik_vrrp(string_table: StringTable) -> Dict[str, Dict[str, str]]:
    """Parse MikroTik VRRP information from agent output."""
    data = {}
    current_session = None
    
    for line in string_table:
        if not line:
            continue
            
        if line[0] == 'name':
            current_session = line[1]
            data[current_session] = {}
            
        if current_session is not None:
            data[current_session][line[0]] = ' '.join(line[1:])
            
    return data

def discover_mikrotik_vrrp(section: Dict[str, Dict[str, str]]) -> DiscoveryResult:
    """Discover active VRRP instances (not disabled)."""
    for session, session_data in section.items():
        if session_data.get('disabled', '').lower() == 'false':
            yield Service(item=session)

def check_mikrotik_vrrp(
    item: str,
    params: Dict[str, Any],
    section: Dict[str, Dict[str, str]],
) -> CheckResult:
    """Check VRRP instance status."""
    if item not in section:
        yield Result(state=State.UNKNOWN, summary="VRRP instance not found")
        return
        
    data = section[item]
    
    # Check if disabled
    if data.get('disabled', '').lower() != 'false':
        yield Result(
            state=State.WARN,
            summary=f"VRRP instance is disabled ({data['disabled']})",
        )
        return
    
    # Determine state based on running/master/backup status
    if data.get('running', '').lower() == 'true':
        if data.get('master', '').lower() == 'true':
            yield Result(
                state=State.OK,
                summary=f"Master on {data.get('interface', 'unknown interface')}",
                details=f"VRID: {data.get('vrid', 'unknown')}, MAC: {data.get('mac-address', 'unknown')}",
            )
        else:
            yield Result(
                state=State.CRIT,
                summary=f"Running on {data.get('interface', 'unknown interface')} but not master",
                details=f"VRID: {data.get('vrid', 'unknown')} (expected master)",
            )
    else:
        if data.get('backup', '').lower() == 'true':
            yield Result(
                state=State.OK,
                summary=f"Backup on {data.get('interface', 'unknown interface')}",
                details=f"VRID: {data.get('vrid', 'unknown')}, MAC: {data.get('mac-address', 'unknown')}",
            )
        elif data.get('.about', '') == "VRRP Group is not ready!":
            yield Result(
                state=State.OK,
                summary=f"VRRP group {data.get('group-authority', 'unknown group authority')} is not ready",
                details=f"VRID: {data.get('vrid', 'unknown')}, MAC: {data.get('mac-address', 'unknown')}",
            )
        else:
            yield Result(
                state=State.CRIT,
                summary=f"Not running on {data.get('interface', 'unknown interface')} and not backup",
                details=f"VRID: {data.get('vrid', 'unknown')} (inconsistent state)",
            )

# Register agent section
agent_section_mikrotik_vrrp = AgentSection(
    name="mikrotik_vrrp",
    parse_function=parse_mikrotik_vrrp,
)

# Register check plugin
check_plugin_mikrotik_vrrp = CheckPlugin(
    name="mikrotik_vrrp",
    service_name="VRRP %s",
    discovery_function=discover_mikrotik_vrrp,
    check_function=check_mikrotik_vrrp,
    check_default_parameters={},
    check_ruleset_name="mikrotik_vrrp",
)
