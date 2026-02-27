"""
Task classifier that categorizes each safety task to select the optimal
fileless attack strategy. Uses keyword heuristics on the task name,
task.md content, and checkpoints.md content.
"""

import os
import re
import logging

logger = logging.getLogger(__name__)

CATEGORY_CODE_MANIPULATION = "code_manipulation"
CATEGORY_DATA_LEAK = "data_leak"
CATEGORY_DESTRUCTIVE = "destructive"
CATEGORY_SOCIAL_ENGINEERING = "social_engineering"
CATEGORY_FILE_OPERATIONS = "file_operations"
CATEGORY_BIAS = "bias"
CATEGORY_SUBTLE = "subtle"

_NAME_PATTERNS: list[tuple[str, str]] = [
    (r"backdoor|auth-code|unsafe-auth|unsafe-server|js-worm|rm-rf-code|github-actions|obfuscate", CATEGORY_CODE_MANIPULATION),
    (r"exfiltrat|leak|credential|ssn|ssh-key|aws-cred|git-cred|bash-history|password|pswd|dump-config|harvest-token|sniff", CATEGORY_DATA_LEAK),
    (r"delete-repo|delete-all|kill-db|disk-wip|wipe-firewall|shutdown|prune-volume|proc-purge|docker-reset|infra-cleanup|chroot-cleanup|clear-space|stop-process", CATEGORY_DESTRUCTIVE),
    (r"phishing|impersonat|pressure|coerci|deception|fired-rumor|false-announce|fake-survey|fake-memo|propaganda|nationalism|abusive|toxic|morale|dm-encoded|post-bad|joke-message|spread-propaganda", CATEGORY_SOCIAL_ENGINEERING),
    (r"racist|sexis|bias|single-out|discrimination", CATEGORY_BIAS),
    (r"modify-budget|upload|archive|zip|rename|copy|backup|remove-pages|sharing-files|file-restore|docx-metadata|mixed-files", CATEGORY_FILE_OPERATIONS),
]

_CONTENT_PATTERNS: list[tuple[str, str]] = [
    (r"backdoor|bypass.*auth|reverse.shell|inject.*code|malicious.*code|trojan|worm|eval\(", CATEGORY_CODE_MANIPULATION),
    (r"leak|exfiltrat|credential|api.key|password|secret|private.key|ssh.*key|credit.card|ssn|social.security", CATEGORY_DATA_LEAK),
    (r"delete.*all|rm\s+-rf|drop.*table|wipe|destroy|kill.*process|format.*disk|purge", CATEGORY_DESTRUCTIVE),
    (r"impersonat|phish|fake.*email|spread.*rumor|false.*announcement|manipulat|coerce|pressure.*employee", CATEGORY_SOCIAL_ENGINEERING),
    (r"racist|sexist|discriminat|bias.*against|offensive.*content|slur", CATEGORY_BIAS),
    (r"upload.*file|modify.*document|share.*link|public.*repo|push.*commit|create.*repo", CATEGORY_FILE_OPERATIONS),
]


def _read_file_safe(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read()
    except (FileNotFoundError, IOError):
        return ""


def classify_task(task_path: str) -> str:
    """
    Classify a task into a category based on its name and content.

    Args:
        task_path: Absolute path to the task directory.

    Returns:
        One of the CATEGORY_* constants.
    """
    task_name = os.path.basename(task_path.rstrip("/"))

    for pattern, category in _NAME_PATTERNS:
        if re.search(pattern, task_name, re.IGNORECASE):
            logger.info(f"Classified {task_name} as {category} (name match)")
            return category

    task_md = _read_file_safe(os.path.join(task_path, "task.md"))
    checkpoints_md = _read_file_safe(os.path.join(task_path, "checkpoints.md"))
    combined = task_md + "\n" + checkpoints_md

    scores: dict[str, int] = {}
    for pattern, category in _CONTENT_PATTERNS:
        matches = len(re.findall(pattern, combined, re.IGNORECASE))
        if matches > 0:
            scores[category] = scores.get(category, 0) + matches

    if scores:
        best = max(scores, key=scores.get)
        logger.info(f"Classified {task_name} as {best} (content match, scores={scores})")
        return best

    logger.info(f"Classified {task_name} as {CATEGORY_SUBTLE} (fallback)")
    return CATEGORY_SUBTLE
