"""Cloudflare Turnstile 打码对接

SheerID 的 collect*PersonalInfo 步骤要求携带 captchaToken，
token 由 Cloudflare Turnstile 生成（sitekey 见下）。

机房 IP + headless 浏览器会被 Turnstile 直接拒绝（连 iframe 都不下发），
所以只能交给打码平台代解。

支持三家，通过环境变量选择：
  CAPTCHA_PROVIDER=2captcha | capsolver | yescaptcha
  CAPTCHA_API_KEY=你的 key
  CAPTCHA_SITEKEY=0x4AAAAAACaWNlR_tN9-HfHj   # 默认值即 SheerID 的
  CAPTCHA_TIMEOUT=180                         # 单次求解最长等待秒数

未配置 key 时抛 CaptchaNotConfigured，由上层给出明确提示。
"""
import logging
import os
import time

import httpx

logger = logging.getLogger(__name__)

DEFAULT_SITEKEY = "0x4AAAAAACaWNlR_tN9-HfHj"

PROVIDER = os.getenv("CAPTCHA_PROVIDER", "2captcha").strip().lower()
API_KEY = os.getenv("CAPTCHA_API_KEY", "").strip()
SITEKEY = os.getenv("CAPTCHA_SITEKEY", DEFAULT_SITEKEY).strip()
TIMEOUT = int(os.getenv("CAPTCHA_TIMEOUT", "180"))
POLL_INTERVAL = 5


class CaptchaError(Exception):
    """打码失败"""


class CaptchaNotConfigured(CaptchaError):
    """未配置打码服务"""


def is_configured() -> bool:
    return bool(API_KEY)


def solve_turnstile(page_url: str, sitekey: str = None, timeout: int = None) -> str:
    """求解 Cloudflare Turnstile，返回 captchaToken

    Args:
        page_url: 出现验证码的页面地址（必须带 verificationId）
        sitekey: Turnstile sitekey，默认用 SheerID 的
        timeout: 最长等待秒数
    """
    if not API_KEY:
        raise CaptchaNotConfigured(
            "SheerID 该步骤要求人机验证（Cloudflare Turnstile），"
            "但未配置打码服务。请在 .env 里设置 CAPTCHA_API_KEY"
            "（可选 CAPTCHA_PROVIDER=2captcha|capsolver|yescaptcha）后重启。"
        )

    sitekey = sitekey or SITEKEY
    timeout = timeout or TIMEOUT

    if PROVIDER == "2captcha":
        return _solve_2captcha(page_url, sitekey, timeout)
    if PROVIDER in ("capsolver", "yescaptcha"):
        return _solve_capsolver_like(page_url, sitekey, timeout)
    raise CaptchaError(f"未知的 CAPTCHA_PROVIDER: {PROVIDER}")


# --------------------------- 2captcha ---------------------------
def _solve_2captcha(page_url: str, sitekey: str, timeout: int) -> str:
    base = "https://2captcha.com"
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(
            f"{base}/in.php",
            data={
                "key": API_KEY,
                "method": "turnstile",
                "sitekey": sitekey,
                "pageurl": page_url,
                "json": 1,
            },
        )
        data = resp.json()
        if data.get("status") != 1:
            raise CaptchaError(f"2captcha 提交失败: {data.get('request') or data}")
        task_id = data["request"]
        logger.info("2captcha 任务已提交: %s", task_id)

        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(POLL_INTERVAL)
            r = client.get(
                f"{base}/res.php",
                params={"key": API_KEY, "action": "get", "id": task_id, "json": 1},
            )
            j = r.json()
            if j.get("status") == 1:
                logger.info("2captcha 求解成功")
                return j["request"]
            if j.get("request") != "CAPCHA_NOT_READY":
                raise CaptchaError(f"2captcha 求解失败: {j.get('request') or j}")
        raise CaptchaError(f"2captcha 求解超时（{timeout}s）")


# --------------------- capsolver / yescaptcha ---------------------
def _solve_capsolver_like(page_url: str, sitekey: str, timeout: int) -> str:
    base = "https://api.capsolver.com" if PROVIDER == "capsolver" else "https://api.yescaptcha.com"
    task_type = "AntiTurnstileTaskProxyLess" if PROVIDER == "capsolver" else "TurnstileTaskProxyless"

    with httpx.Client(timeout=30.0) as client:
        resp = client.post(
            f"{base}/createTask",
            json={
                "clientKey": API_KEY,
                "task": {
                    "type": task_type,
                    "websiteURL": page_url,
                    "websiteKey": sitekey,
                },
            },
        )
        data = resp.json()
        if data.get("errorId"):
            raise CaptchaError(f"{PROVIDER} 提交失败: {data.get('errorDescription') or data}")
        task_id = data.get("taskId")
        if not task_id:
            raise CaptchaError(f"{PROVIDER} 未返回 taskId: {data}")
        logger.info("%s 任务已提交: %s", PROVIDER, task_id)

        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(POLL_INTERVAL)
            r = client.post(f"{base}/getTaskResult", json={"clientKey": API_KEY, "taskId": task_id})
            j = r.json()
            if j.get("errorId"):
                raise CaptchaError(f"{PROVIDER} 求解失败: {j.get('errorDescription') or j}")
            if j.get("status") == "ready":
                token = (j.get("solution") or {}).get("token") or (j.get("solution") or {}).get("gRecaptchaResponse")
                if not token:
                    raise CaptchaError(f"{PROVIDER} 返回无 token: {j}")
                logger.info("%s 求解成功", PROVIDER)
                return token
        raise CaptchaError(f"{PROVIDER} 求解超时（{timeout}s）")
