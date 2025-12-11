__all__ = ['InvalidFormatError', 'MissingVariableError']


class MissingVariableError(ValueError):
    """Exception raised when a required environment variable is missing."""

    def __init__(self, name: str) -> None:
        """Initialize the exception with the missing variable name."""
        super().__init__(f'{name} environment variable is required')


class InvalidFormatError(ValueError):
    """Exception raised when an environment variable has an invalid format."""

    def __init__(self, name: str, value: str, hint: str | None = None) -> None:
        """Initialize the exception with the variable name and invalid value."""
        super().__init__(f'Invalid {name} format: {value}\n{hint=}')
