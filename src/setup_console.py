from typing import Any

import rampy.console


def get_console(**kwds: Any):
    return rampy.console.bind(**kwds)


console = rampy.console.root()
