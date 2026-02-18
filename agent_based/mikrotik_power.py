#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
    StringTable,
)
from typing import Any, Dict, List, Tuple

def parse_mikrotik_power(string_table: StringTable) -> Dict[str, Any]:
    """Parse MikroTik power supply information from agent output."""
    data = {
        'psus': {},
        'power-consumption': 0.0
    }
    
    for line in string_table:
        if not line:
            continue
            
        # Normalize metric names
        metric = line[0]
        if metric in ['current', 'voltage']:
            metric = f'psu0-{metric}'
            
        if 'psu' not in metric:
            continue
            
        try:
            psu, metric_type = metric.split('-')
            psu = psu.upper()
            value = float(line[1])
            
            # Convert mA to A if needed
            if metric_type == 'current' and value > 100:
                value /= 1000
                
            # Store PSU data
            if psu not in data['psus']:
                data['psus'][psu] = {}
            data['psus'][psu][metric_type] = value
            
        except (ValueError, IndexError):
            continue
    
    # Calculate total power consumption
    for psu in data['psus'].values():
        data['power-consumption'] += psu.get('current', 0) * psu.get('voltage', 0)
    
    return data

def discover_mikrotik_power(section: Dict[str, Any]) -> DiscoveryResult:
    """Discover power service based on available PSUs."""
    yield Service(parameters={'psu_count': len(section['psus'])})

def check_mikrotik_power(
    params: Dict[str, Any],
    section: Dict[str, Any],
) -> CheckResult:
    """Check power supply status and metrics."""
    if not section.get('psus'):
        yield Result(state=State.UNKNOWN, summary="No power supply data found")
        return
        
    psu_count = len(section['psus'])
    expected_count = params.get('psu_count', 0)
    crit_voltage = params.get('crit_voltage', 10)
    
    # Check PSU count mismatch
    if expected_count != 0 and psu_count != expected_count:
        yield Result(
            state=State.WARN,
            summary=f"{psu_count} PSUs (expected {expected_count})",
        )
    else:
        yield Result(
            state=State.OK,
            summary=f"{psu_count} PSUs",
        )
    
    # Check individual PSUs
    total_current = 0.0
    max_voltage = 0.0
    details = []
    
    for psu_name, psu_data in section['psus'].items():
        voltage = psu_data.get('voltage', 0)
        current = psu_data.get('current', 0)
        
        # Check for low voltage
        if voltage < crit_voltage:
            yield Result(
                state=State.CRIT,
                summary=f"{psu_name} voltage {voltage}V (below {crit_voltage}V)",
            )
        
        details.append(f"{psu_name}: {voltage:.2f}V / {current:.2f}A")
        total_current += current
        max_voltage = max(max_voltage, voltage)
    
    yield Result(
        state=State.OK,
        notice="\n".join(details),
    )
    
    # Power consumption metrics
    power = section.get('power-consumption', 0)
    if power > 0:
        yield Result(
            state=State.OK,
            summary=f"Power: {power:.2f}W",
        )
        yield Metric(
            name="power",
            value=power,
        )
    else:
        yield Result(
            state=State.OK,
            summary=f"Voltage: {max_voltage:.2f}V",
        )
    
    # Additional metrics
    if total_current > 0:
        yield Metric(
            name="current_total",
            value=total_current,
        )
    
    if max_voltage > 0:
        yield Metric(
            name="voltage_max",
            value=max_voltage,
        )

# Register agent section
agent_section_mikrotik_power = AgentSection(
    name="mikrotik_power",
    parse_function=parse_mikrotik_power,
)

# Register check plugin
check_plugin_mikrotik_power = CheckPlugin(
    name="mikrotik_power",
    service_name="Power Usage",
    discovery_function=discover_mikrotik_power,
    check_function=check_mikrotik_power,
    check_default_parameters={
        "crit_voltage": 10,
    },
    check_ruleset_name="mikrotik_power",
)
