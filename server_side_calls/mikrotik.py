import os
from cmk.server_side_calls.v1 import SpecialAgentConfig, SpecialAgentCommand, noop_parser


def _mikrotik_commands(params, host_config):
    args = []

    # ----------------------------
    # Mandatory parameters
    # ----------------------------

    args += ["--user", params["user"]]
    args += ["--pass", params["password"]]

    # ----------------------------
    # Optional connection parameters
    # ----------------------------

    if params.get("no-ssl"):
        args.append("--no-ssl")

    if params.get("skip-cert-check"):
        args.append("--skip-cert-check")

    if params.get("rest"):
        args.append("--rest")

    args += ["--connect", str(params.get("connect", 8729))]

    # ----------------------------
    # Infos handling
    # ----------------------------

    modules = []
    infos = params.get("infos", {})

    for name, value in infos.items():

        # Simple modules
        if name != "firewall":
            if value:
                modules.append(name)

        # Firewall module
        else:
            if isinstance(value, dict) and value.get("enabled"):
                if value.get("show-disabled"):
                    modules.append("firewall:show-disabled")
                else:
                    modules.append("firewall")

    if modules:
        args += ["--modules", ",".join(modules)]

    # ----------------------------
    # Resolve IP or hostname
    # ----------------------------

    ipaddress = None

    if host_config.ipv4_config and host_config.ipv4_config.address:
        ipaddress = host_config.ipv4_config.address
    elif host_config.ipv6_config and host_config.ipv6_config.address:
        ipaddress = host_config.ipv6_config.address
    else:
        ipaddress = host_config.name

    if ipaddress is None:
        raise ValueError("No IP address or hostname found in HostConfig")

    args.append(ipaddress)

    # ----------------------------
    # Execute special agent
    # ----------------------------

    yield SpecialAgentCommand(command_arguments=args)


special_agent_mikrotik = SpecialAgentConfig(
    name="mikrotik",
    parameter_parser=noop_parser,
    commands_function=_mikrotik_commands,
)
