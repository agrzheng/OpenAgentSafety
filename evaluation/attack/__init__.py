from attack.classifier import classify_task
from attack.strategies import STRATEGIES, get_strategy, STEGO_STRATEGIES, get_stego_strategy
from attack.rewriter import rewrite_task, rewrite_task_stego
from attack.fake_user import AdaptiveFakeUser, StegoFakeUser
from attack.instruction import build_instruction, build_instruction_stego
from attack.steganography import (
    encode_zero_width,
    decode_zero_width,
    interleave_zero_width,
    encode_unicode_tags,
    decode_unicode_tags,
    append_unicode_tags,
    embed_html_comment,
    create_poisoned_config,
    wrap_with_cleanup,
)
from attack.cover_tasks import generate_cover_task
