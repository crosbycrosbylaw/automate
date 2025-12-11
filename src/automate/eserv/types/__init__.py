from typing import TYPE_CHECKING

__all__ = [
    'BaseFields',
    'BatchResult',
    'CaseMatch',
    'Config',
    'CredentialsConfig',
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
    'MonitoringFields',
    'NotificationConfig',
    'Notifier',
    'OAuthCredential',
    'PartialEmailRecord',
    'PartyExtractor',
    'PathsConfig',
    'PipelineError',
    'PipelineStage',
    'ProcessedResult',
    'SMTPFields',
    'StatusFlag',
    'TokenManager',
    'UploadInfo',
    'UploadStatus',
    'ValidationHint',
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
