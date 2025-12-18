from typing import TYPE_CHECKING

__all__ = [
    'AuthError',
    'BatchResult',
    'CaseMatch',
    'Config',
    'CredentialsConfig',
    'DataclassInstance',
    'DataclassType',
    'DocumentDownloadError',
    'DocumentExtractionError',
    'DocumentUploadError',
    'DownloadInfo',
    'DropboxManager',
    'EmailAddress',
    'EmailInfo',
    'EmailParseError',
    'EmailProcessor',
    'EmailRecord',
    'EnvStatus',
    'ErrorTracker',
    'FolderMatcher',
    'FolderResolutionError',
    'GraphRequest',
    'IndexCache',
    'IntermediaryResult',
    'InvalidFormatError',
    'MSALManager',
    'MissingVariableError',
    'Notifier',
    'OAuthCredential',
    'PartialEmailRecord',
    'PartyExtractor',
    'PathsConfig',
    'PipelineError',
    'PipelineStage',
    'ProcessedResult',
    'StateTracker',
    'StatusFlag',
    'StrPath',
    'TokenManager',
    'UploadInfo',
    'UploadStatus',
    'ValidationHint',
]


from automate.eserv.config.main import *
from automate.eserv.config.types import *
from automate.eserv.errors.types import *
from automate.eserv.monitor.types import *
from automate.eserv.util.types import *

from .enums import *
from .results import *
from .structs import *

if TYPE_CHECKING:
    __all__ += [
        'BaseConfig',
        'CredentialMap',
        'CredentialType',
        'CredentialsJSON',
        'DropboxCredential',
        'ErrorDict',
        'MSALCredential',
        'MonitoringConfig',
        'ProcessStatus',
        'ProcessedResultDict',
        'SMTPConfig',
    ]

    from .typechecking import *
