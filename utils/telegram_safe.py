"""Telegram 消息安全包装

背景：python-telegram-bot 默认 read_timeout 只有 5s，网络抖动时
reply_text / edit_text 会抛 telegram.error.TimedOut。异常一旦抛出，
调用方的整个处理流程（例如 SheerID 验证）就会被中断，用户永远停在
"请稍候" 那条消息上。

这里把单条消息的收发失败降级为 warning：消息发不出去不影响业务逻辑，
结果至少会写进日志和数据库。
"""
import logging

from telegram.error import TelegramError

logger = logging.getLogger(__name__)


async def safe_reply(message, text: str):
    """发送消息，失败返回 None 而不是抛异常"""
    if message is None:
        return None
    try:
        return await message.reply_text(text)
    except TelegramError as e:
        logger.warning("发送消息失败（已忽略，流程继续）: %s", e)
        return None


async def safe_edit(message, text: str) -> bool:
    """编辑消息，失败返回 False 而不是抛异常"""
    if message is None:
        logger.info("原消息不可用，结果未回显: %s", text[:120].replace("\n", " "))
        return False
    try:
        await message.edit_text(text)
        return True
    except TelegramError as e:
        logger.warning("编辑消息失败（已忽略，流程继续）: %s", e)
        return False
