from typing import TYPE_CHECKING

__all__ = [
    'BatchResult',
    'CaseMatch',
    'Config',
    'CredentialsJSON',
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
    'EmailState',
    'ErrorTracker',
    'FolderMatcher',
    'FolderResolutionError',
    'GraphClient',
    'IndexCache',
    'IntermediaryResult',
    'InvalidFormatError',
    'MSALManager',
    'MissingVariableError',
    'NotificationConfig',
    'Notifier',
    'OAuthCredential',
    'PartialEmailRecord',
    'PartyExtractor',
    'PipelineError',
    'PipelineStage',
    'ProcessedResult',
    'StatusFlag',
    'TextExtractor',
    'TokenManager',
    'UploadInfo',
    'UploadStatus',
]


from automate.eserv.config.types import *
from automate.eserv.errors.types import *
from automate.eserv.monitor.types import *
from automate.eserv.util.types import *

from .enums import *
from .results import *
from .structs import *

if TYPE_CHECKING:
    __all__ += [
        'CredentialType',
        'DropboxCredential',
        'ErrorDict',
        'MSALCredential',
        'ProcessStatus',
        'ProcessedResultDict',
        'SMTPConfig',
    ]

    from .typechecking import *
