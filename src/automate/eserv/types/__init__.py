from typing import TYPE_CHECKING

__all__ = [
    'BatchResult',
    'CacheConfig',
    'CaseMatch',
    'Config',
    'CredentialManager',
    'CredentialManager',
    'DocumentDownloadError',
    'DocumentExtractionError',
    'DocumentUploadError',
    'DownloadInfo',
    'DropboxManager',
    'EmailInfo',
    'EmailParseError',
    'EmailProcessor',
    'EmailRecord',
    'EmailState',
    'EmailStateConfig',
    'ErrorTracker',
    'FolderMatcher',
    'FolderResolutionError',
    'GraphClient',
    'IndexCache',
    'IntermediaryResult',
    'InvalidFormatError',
    'MicrosoftAuthManager',
    'MissingVariableError',
    'MonitoringConfig',
    'NotificationConfig',
    'Notifier',
    'OAuthCredential',
    'PartialEmailRecord',
    'PartyExtractor',
    'PathsConfig',
    'PipelineError',
    'PipelineStage',
    'ProcessedResult',
    'RefreshHandler',
    'StatusFlag',
    'TextExtractor',
    'TokenManager',
    'UploadInfo',
    'UploadStatus',
]


from automate.eserv.errors.types import *
from automate.eserv.monitor.types import *
from automate.eserv.util.types import *

from .enums import *
from .results import *
from .structs import *

if TYPE_CHECKING:
    __all__ += [
        'CredentialType',
        'ErrorDict',
        'ProcessStatus',
        'ProcessedResultDict',
    ]

    from .typechecking import *
