from __future__ import annotations

from typing import TYPE_CHECKING, Literal, NewType, no_type_check, overload

if TYPE_CHECKING:
    from automate.eserv.types import ErrorDict

StatusFlag = NewType('StatusFlag', dict[Literal['id', 'value'], str])


@overload
def status_flag_factory(*, success: Literal[True] = True) -> StatusFlag: ...
@overload
def status_flag_factory(error: ErrorDict) -> StatusFlag: ...
@no_type_check
def status_flag_factory(
    error: ErrorDict | None = None,
    *,
    success: Literal[True] | None = None,
) -> StatusFlag:
    """Create a status flag with the given value.

    Args:
        error (ErrorDict):
            The error dictionary for an exception that occurred in the pipeline.
            Used in formatting the value of the flag.
        success (Literal[True]):
            Indicates that no error occurred in pipeline execution.

    Returns:
        A `StatusFlag` dictionary with id and value.

    """
    out = {'id': 'String {00020329-0000-0000-C000-000000000046} Name eserv_flag'}

    if error is None or success is True:
        out['value'] = '$eserv_success'
    elif (category := error['category']).startswith('$eserv_error:'):
        out['value'] = category
    else:
        out['value'] = f'$eserv_error:{category}'

    return out
