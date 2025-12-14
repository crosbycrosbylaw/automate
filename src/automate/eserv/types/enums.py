__all__ = ['EnvStatus', 'PipelineStage', 'UploadStatus']
from enum import Enum

from automate.eserv.config._paths import EnvStatus
from automate.eserv.errors.pipeline import PipelineStage


class UploadStatus(Enum):
    """Upload result status."""

    SUCCESS = 'success'
    NO_WORK = 'no_work'
    MANUAL_REVIEW = 'manual_review'
    ERROR = 'error'
