#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from cmk.gui.i18n import _
from cmk.gui.plugins.wato import rulespec_registry
from cmk.gui.plugins.wato.datasource_programs import (
    HostRulespec,
    RulespecGroupDatasourceProgramsHardware,
)
from cmk.gui.valuespec import (
    Dictionary,
    TextInput,
    DropdownChoice,
    Integer,
    Password,
)

# Register the MikroTik RouterOS special agent rule
rulespec_registry.register(
    HostRulespec(
        group=RulespecGroupDatasourceProgramsHardware,
        name="special_agents:mikrotik",
        valuespec=lambda: Dictionary(
            title=_("MikroTik RouterOS"),
            help=_("This rule activates an agent that collects information from MikroTik RouterOS API."),
            optional_keys=False,
            elements=[

                # -------------------------------------------------
                # Connection parameters (always visible)
                # -------------------------------------------------

                ("user", TextInput(
                    title=_("Username"),
                    allow_empty=False,
                )),

                ("password", Password(
                    title=_("Password"),
                    allow_empty=False,
                )),

                ("rest", DropdownChoice(
                    title=_("API type"),
                    choices=[
                        (False, _("RouterOS API (Default)")),
                        (True, _("RESTful API")),
                    ],
                    default_value=False,
                )),

                ("no-ssl", DropdownChoice(
                    title=_("Use SSL"),
                    choices=[
                        (False, _("Yes (Default)")),
                        (True, _("No")),
                    ],
                    default_value=False,
                )),

                ("skip-cert-check", DropdownChoice(
                    title=_("Validate certificate"),
                    choices=[
                        (False, _("Yes (Default)")),
                        (True, _("No")),
                    ],
                    default_value=False,
                )),

                ("connect", Integer(
                    title=_("TCP port number"),
                    help=_("Default: 8729 (SSL) or 8728 (no SSL)"),
                    default_value=8729,
                    minvalue=1,
                    maxvalue=65535,
                )),

                # -------------------------------------------------
                # Infos section
                # -------------------------------------------------

                ("infos", Dictionary(
                    title=_("Retrieve information about"),
                    optional_keys=False,
                    elements=[

                        ("bgp", DropdownChoice(
                            title=_("BGP Sessions"),
                            choices=[
                                (True, _("Enabled")),
                                (False, _("Disabled")),
                            ],
                            default_value=False,
                        )),

                        ("ospf", DropdownChoice(
                            title=_("OSPF Neighbors"),
                            choices=[
                                (True, _("Enabled")),
                                (False, _("Disabled")),
                            ],
                            default_value=False,
                        )),

                        ("vrrp", DropdownChoice(
                            title=_("VRRP Info"),
                            choices=[
                                (True, _("Enabled")),
                                (False, _("Disabled")),
                            ],
                            default_value=False,
                        )),

                        ("health", DropdownChoice(
                            title=_("RouterOS Health"),
                            choices=[
                                (True, _("Enabled")),
                                (False, _("Disabled")),
                            ],
                            default_value=False,
                        )),

                        ("board", DropdownChoice(
                            title=_("RouterOS Board Info"),
                            choices=[
                                (True, _("Enabled")),
                                (False, _("Disabled")),
                            ],
                            default_value=False,
                        )),

                        ("ipsec", DropdownChoice(
                            title=_("IPsec"),
                            choices=[
                                (True, _("Enabled")),
                                (False, _("Disabled")),
                            ],
                            default_value=False,
                        )),

                        ("file", DropdownChoice(
                            title=_("Local File Age"),
                            choices=[
                                (True, _("Enabled")),
                                (False, _("Disabled")),
                            ],
                            default_value=False,
                        )),

                        ("license", DropdownChoice(
                            title=_("License Key (CHR)"),
                            choices=[
                                (True, _("Enabled")),
                                (False, _("Disabled")),
                            ],
                            default_value=False,
                        )),

                        ("firewall", Dictionary(
                            title=_("Firewall Rules"),
                            optional_keys=False,
                            elements=[
                                ("enabled", DropdownChoice(
                                    title=_("Enable firewall monitoring"),
                                    choices=[
                                        (True, _("Enabled")),
                                        (False, _("Disabled")),
                                    ],
                                    default_value=False,
                                )),
                                ("show-disabled", DropdownChoice(
                                    title=_("Show disabled firewall rules"),
                                    choices=[
                                        (True, _("Yes")),
                                        (False, _("No")),
                                    ],
                                    default_value=False,
                                )),
                            ],
                        )),
                    ],
                )),
            ],
        ),
    )
)
