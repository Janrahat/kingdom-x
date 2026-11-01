"""Phone Number Intelligence — numbering-plan facts only.

This module answers questions that are genuinely public:

* which country an E.164 country code belongs to,
* whether a number is structurally valid for that country's numbering plan,
* which line type the prefix indicates (mobile / fixed / toll-free / VoIP),
* how to format it in the standard ways.

It cannot and does not reveal a subscriber's identity, name, address, live
location, call records or messages. Those are not obtainable from a phone number
and any product claiming otherwise is either guessing or breaching privacy law.
"""

from kingdomx.phone.numbering import (
    NumberInfo,
    NumberingPlan,
    parse_number,
    PLANS,
    supported_countries,
    validate_e164,
)

__all__ = [
    "NumberInfo",
    "NumberingPlan",
    "parse_number",
    "PLANS",
    "supported_countries",
    "validate_e164",
]
