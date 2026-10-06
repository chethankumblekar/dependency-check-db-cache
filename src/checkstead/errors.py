class ChecksteadError(Exception):
    """A failure the CLI reports on stderr and turns into an exit code."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class SnapshotRefused(ChecksteadError):
    """The snapshot is not the one this pin will scan with."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=2)


class RefusedHost(ChecksteadError):
    """The scan client was pointed at a host it must not call."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=2)
