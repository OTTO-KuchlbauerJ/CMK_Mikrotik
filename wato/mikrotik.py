#!/usr/bin/env python3
#
# part of mkp package "mikrotik"
# see package description for details
#

from cmk.gui.i18n import _
from cmk.gui.valuespec import (
    TextAscii,
    Integer,
    Tuple,
    DropdownChoice,
    Dictionary,
    ListOfStrings,
    Age,
)

from cmk.gui.plugins.wato import (
    CheckParameterRulespecWithItem,
    CheckParameterRulespecWithoutItem,
    rulespec_registry,
    RulespecGroupCheckParametersApplications,
)

# -------------------------
# MikroTik Fan
# -------------------------

rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="mikrotik_fan",
        group=RulespecGroupCheckParametersApplications,
        item_spec=lambda: TextAscii(title=_("MikroTik Fan")),
        parameter_valuespec=lambda: Dictionary(
            title=_("MikroTik Fan"),
            help=_("Activate special agent mikrotik to use this."),
            elements=[
                (
                    "output_metrics",
                    DropdownChoice(
                        title=_("Performance Graph"),
                        help=_("If set to <b>disable</b> on existing fans "
                               "delete RRD files to completely remove graphs."),
                        choices=[
                            (True, _("enable (default)")),
                            (False, _("disable")),
                        ],
                        default_value=True,
                    ),
                ),
                (
                    "lower",
                    Tuple(
                        title=_("Lower levels"),
                        help=_("Lower levels for the fan speed"),
                        elements=[
                            Integer(
                                title=_("Warning if below"),
                                unit=_("rpm"),
                                default_value=2000,
                            ),
                            Integer(
                                title=_("Critical if below"),
                                unit=_("rpm"),
                                default_value=1000,
                            ),
                        ],
                    ),
                ),
            ],
        ),
        title=lambda: _("MikroTik Fan"),
    )
)

# -------------------------
# MikroTik RouterOS Version
# -------------------------

rulespec_registry.register(
    CheckParameterRulespecWithoutItem(
        check_group_name="mikrotik_board",
        group=RulespecGroupCheckParametersApplications,
        parameter_valuespec=lambda: Dictionary(
            title=_("MikroTik RouterOS"),
            help=_("Activate special agent mikrotik to use this."),
            elements=[
                (
                    "min_version",
                    TextAscii(
                        title=_("Minimum Version"),
                        help=_("If set check will go WARN if installed version is lower"),
                        regex=r"^[0-9]*\.[0-9]",
                        regex_error=_("Enter a correct version number (e.g. "
                                      "<b><tt>Major.Minor</tt></b> or "
                                      "<b><tt>Major.Minor.Patch</tt></b>)"),
                        default_value="0.0",
                    ),
                )
            ],
        ),
        title=lambda: _("MikroTik RouterOS"),
    )
)

# -------------------------
# MikroTik File Age
# -------------------------

rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="mikrotik_file",
        group=RulespecGroupCheckParametersApplications,
        item_spec=lambda: TextAscii(title=_("MikroTik File")),
        parameter_valuespec=lambda: Dictionary(
            title=_("MikroTik File"),
            help=_("Activate special agent mikrotik to use this."),
            elements=[
                (
                    "file_age",
                    Tuple(
                        title=_("Age of File Creation"),
                        elements=[
                            Age(title=_("Warning if older than"), default_value=90000),
                            Age(title=_("Critical if older than"), default_value=176400),
                        ],
                    ),
                ),
                (
                    "pattern",
                    TextAscii(
                        title=_("Time Pattern (see inline help for examples)"),
                        help=_("Time format code for <tt>creation-time</tt> as returned by API:"
                               "<br>v7: <tt>%b/%d/%Y %H:%M:%S</tt>"
                               "<br>v8: <tt>%Y-%m-%d %H:%M:%S</tt>"
                               "<br>leave empty for autodetection"),
                        allow_empty=False,
                        default_value="",
                    ),
                ),
            ],
        ),
        title=lambda: _("MikroTik File"),
    )
)

# -------------------------
# MikroTik IPsec
# -------------------------

rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="mikrotik_ipsec",
        group=RulespecGroupCheckParametersApplications,
        item_spec=lambda: TextAscii(title=_("MikroTik IPsec")),
        parameter_valuespec=lambda: Dictionary(
            title=_("MikroTik IPsec"),
            help=_("Activate special agent mikrotik to use this."),
            elements=[
                (
                    "ok_states",
                    ListOfStrings(
                        title=_("Security Association states considered OK"),
                        default_value=["dying", "mature"],
                        help=_("States that are OK."),
                    ),
                )
            ],
        ),
        title=lambda: _("MikroTik IPsec"),
    )
)
