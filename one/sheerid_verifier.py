"""SheerID 学生验证主程序"""
import re
import random
import logging
import os
import httpx
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, unquote

from utils.captcha import solve_turnstile

from . import config
from .name_generator import NameGenerator, generate_birth_date
from .img_generator import generate_image, generate_psu_email

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# SheerID 专用代理：机房 IP 会被 fraudRulesReject，配了就走代理
_SHERID_PROXY = os.getenv("SHERID_PROXY") or None

# 浏览器 UA：裸 python-httpx UA 会被风控直接标记
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# 国家代码 -> 展示名（SheerID 前端 countryChoice.label 用，服务端只看 value）
_COUNTRY_LABELS = {
    "US": "United States",
    "CN": "China",
    "JP": "Japan",
    "GB": "United Kingdom",
    "CA": "Canada",
    "AU": "Australia",
    "DE": "Germany",
    "FR": "France",
    "TW": "Taiwan",
    "HK": "Hong Kong",
    "SG": "Singapore",
    "KR": "South Korea",
}


class SheerIDVerifier:
    """SheerID 学生身份验证器"""

    def __init__(self, verification_id: str, program_id: Optional[str] = None):
        self.verification_id = verification_id
        # programId 优先用用户链接里的（永远最新），取不到才回落到 config
        self.program_id = program_id or config.PROGRAM_ID
        logger.info("验证器: vid=%s programId=%s", self.verification_id, self.program_id)
        self.device_fingerprint = self._generate_device_fingerprint()
        self.http_client = httpx.Client(timeout=30.0, proxy=_SHERID_PROXY)

    def __del__(self):
        if hasattr(self, "http_client"):
            self.http_client.close()

    @staticmethod
    def _generate_device_fingerprint() -> str:
        chars = '0123456789abcdef'
        return ''.join(random.choice(chars) for _ in range(32))

    @staticmethod
    def normalize_url(url: str) -> str:
        """规范化 URL（保留原样）"""
        return url

    @staticmethod
    def parse_verification_id(url: str) -> Optional[str]:
        match = re.search(r"verificationId=([a-f0-9]+)", url, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def parse_program_id(url: str) -> Optional[str]:
        """从验证链接中提取 programId（形如 /verify/<24位hex>/）

        用户发来的链接本身就带当前有效的 programId，优先使用它，
        避免 config.PROGRAM_ID 过期导致认证失败。
        """
        match = re.search(r"/verify/([a-f0-9]{24})(?:[/?#]|$)", url, re.IGNORECASE)
        return match.group(1) if match else None

    def _verify_page_url(self) -> str:
        return f"{config.SHEERID_BASE_URL}/verify/{self.program_id}/?verificationId={self.verification_id}"

    def _warm_up_session(self) -> None:
        """先访问验证页，拿到 JSESSIONID / sid-verificationId 等会话 cookie

        SheerID 风控会检查提交请求是否来自同一会话。裸 httpx 直连
        （无 cookie、无 Referer）会被直接判 fraudRulesReject。
        """
        try:
            resp = self.http_client.get(
                self._verify_page_url(),
                headers={
                    "User-Agent": _BROWSER_UA,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                },
                timeout=30.0,
            )
            logger.info(
                "会话预热: HTTP %s, cookies=%s",
                resp.status_code,
                list(self.http_client.cookies.keys()),
            )
        except Exception as e:
            logger.warning("会话预热失败（继续执行）: %s", e)

    def _sheerid_request(
        self, method: str, url: str, body: Optional[Dict] = None
    ) -> Tuple[Dict, int]:
        """发送 SheerID API 请求"""
        headers = {
            "Content-Type": "application/json",
        }

        try:
            response = self.http_client.request(
                method=method, url=url, json=body, headers=headers
            )
            try:
                data = response.json()
            except Exception:
                data = response.text
            return data, response.status_code
        except Exception as e:
            logger.error(f"SheerID 请求失败: {e}")
            raise

    @staticmethod
    def _playwright_proxy():
        """把 socks5://user:pass@host:port 拆成 Playwright 的 proxy 配置"""
        if not _SHERID_PROXY:
            return None
        u = urlparse(_SHERID_PROXY)
        cfg = {"server": f"{u.scheme}://{u.hostname}:{u.port}"}
        if u.username:
            cfg["username"] = unquote(u.username)
            cfg["password"] = unquote(u.password or "")
        return cfg

    def _submit_step2_in_browser(self, body: Dict) -> Tuple[Dict, int]:
        """用真实 Chromium 打开验证页再提交

        该 program 开了 ThreatMetrix(threatMetrixEnabled) 与 IPQS 设备指纹
        (ipqsDeviceFingerprintEnabled)，服务端会核对本次验证是否伴随正常的
        设备采集会话。纯 httpx 提交没有这些会话，会被 fraudRulesReject。
        所以这里先用浏览器真实加载验证页触发采集，再在页面上下文里 fetch，
        保证 cookie / Origin / 出口 IP / 设备会话全部一致。
        """
        from playwright.sync_api import sync_playwright

        page_url = self._verify_page_url()
        api_url = (
            f"{config.SHEERID_BASE_URL}/rest/v2/verification/"
            f"{self.verification_id}/step/collectStudentPersonalInfo"
        )
        js = """
        async ({api, body}) => {
            const r = await fetch(api, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json, text/plain, */*'
                },
                credentials: 'include',
                body: JSON.stringify(body)
            });
            let data;
            try { data = await r.json(); } catch (e) { data = await r.text(); }
            return { status: r.status, data: data };
        }
        """
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-blink-features=AutomationControlled",
                ],
                proxy=self._playwright_proxy(),
            )
            try:
                ctx = browser.new_context(
                    user_agent=_BROWSER_UA,
                    locale="en-US",
                    viewport={"width": 1366, "height": 900},
                    timezone_id="America/New_York",
                )
                ctx.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
                page = ctx.new_page()
                last_err = None
                for attempt in range(1, 4):
                    try:
                        page.goto(page_url, wait_until="domcontentloaded", timeout=90000)
                        last_err = None
                        break
                    except Exception as e:
                        last_err = e
                        logger.warning("打开验证页失败（第 %s 次）: %s", attempt, e)
                        page.wait_for_timeout(3000)
                if last_err is not None:
                    raise last_err
                try:
                    page.wait_for_load_state("networkidle", timeout=25000)
                except Exception:
                    pass
                # 再给 ThreatMetrix / IPQS 的 beacon 一点时间上报
                page.wait_for_timeout(6000)
                logger.info("✅ 浏览器设备采集完成，页面内提交 step2")
                res = page.evaluate(js, {"api": api_url, "body": body})
                return res.get("data"), int(res.get("status") or 0)
            finally:
                try:
                    browser.close()
                except Exception:
                    pass

    def _upload_to_s3(self, upload_url: str, img_data: bytes) -> bool:
        """上传 PNG 到 S3"""
        try:
            headers = {"Content-Type": "image/png"}
            response = self.http_client.put(
                upload_url, content=img_data, headers=headers, timeout=60.0
            )
            return 200 <= response.status_code < 300
        except Exception as e:
            logger.error(f"S3 上传失败: {e}")
            return False

    def verify(
        self,
        first_name: str = None,
        last_name: str = None,
        email: str = None,
        birth_date: str = None,
        school_id: str = None,
    ) -> Dict:
        """执行验证流程"""
        try:
            current_step = "initial"
            self._warm_up_session()


            if not first_name or not last_name:
                name = NameGenerator.generate()
                first_name = name["first_name"]
                last_name = name["last_name"]

            school_id = school_id or config.DEFAULT_SCHOOL_ID
            school = config.SCHOOLS[school_id]

            if not email:
                email = generate_psu_email(first_name, last_name)
            if not birth_date:
                birth_date = generate_birth_date()

            logger.info(f"学生信息: {first_name} {last_name}")
            logger.info(f"邮箱: {email}")
            logger.info(f"学校: {school['name']}")
            logger.info(f"生日: {birth_date}")
            logger.info(f"验证 ID: {self.verification_id}")

            # 生成学生证 PNG
            logger.info("步骤 1/4: 生成学生证 PNG...")
            img_data = generate_image(first_name, last_name, school_id)
            file_size = len(img_data)
            logger.info(f"✅ PNG 大小: {file_size / 1024:.2f}KB")

            # 提交学生信息
            logger.info("步骤 2/4: 提交学生信息...")

            # 先读一次验证对象，拿它创建时的 locale / country / 可选学籍状态
            info, _ = self._sheerid_request(
                "GET",
                f"{config.SHEERID_BASE_URL}/rest/v2/verification/{self.verification_id}",
            )
            if not isinstance(info, dict):
                info = {}
            if info.get("currentStep") == "error":
                raise Exception(
                    f"该验证链接已失效: {info.get('errorIds')} "
                    f"({info.get('errorDetailId')})，请去 one.google.com/ai-student 重新生成"
                )
            v_country = (info.get("country") or "US").upper()
            v_locale = info.get("locale") or "en-US"
            # 前端逻辑：只有 availableStatuses 含 GRADUATE 时才渲染学籍下拉，
            # 否则 viewModel.statuses 固定为空数组。对齐真实 UI 行为。
            v_statuses = []
            logger.info(
                "验证对象: locale=%s country=%s availableStatuses=%s attempts=%s",
                v_locale, v_country, info.get("availableStatuses"),
                info.get("instantMatchAttempts"),
            )

            step2_body = {
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "phoneNumber": "",
                "birthDate": birth_date,
                # 服务端白名单：statuses/lastName/ipAddressExtended/birthDate/metadata/
                # externalUserId/organization/country/phoneNumber/locale/firstName/email/
                # captchaToken/ipAddress/email2/cvecNumber/deviceFingerprintHash
                # 前端的 countryChoice / localeChoice 会被判 Unrecognized property
                "country": v_country,
                "locale": v_locale,
                "organization": {
                    "id": int(school_id),
                    "idExtended": school["idExtended"],
                    "name": school["name"],
                },
                "statuses": v_statuses,
                "deviceFingerprintHash": self.device_fingerprint,
                "metadata": {
                    "marketConsentValue": False,
                    "refererUrl": self._verify_page_url(),
                    "verificationId": self.verification_id,
                    "flags": '{"collect-info-step-email-first":"default","doc-upload-considerations":"default","doc-upload-may24":"default","doc-upload-redesign-use-legacy-message-keys":false,"docUpload-assertion-checklist":"default","font-size":"default","include-cvec-field-france-student":"not-labeled-optional"}',
                    "submissionOptIn": "By submitting the personal information above, I acknowledge that my personal information is being collected under the privacy policy of the business from which I am seeking a discount",
                },
            }

            # SheerID 该步骤要求 Cloudflare Turnstile token，交给打码平台代解
            step2_body["captchaToken"] = solve_turnstile(self._verify_page_url())

            # 关键：走真实 Chromium，让 ThreatMetrix / IPQS 拿到设备会话
            step2_data, step2_status = self._submit_step2_in_browser(step2_body)

            if step2_status != 200:
                raise Exception(f"步骤 2 失败 (状态码 {step2_status}): {step2_data}")
            if step2_data.get("currentStep") == "error":
                error_msg = ", ".join(step2_data.get("errorIds", ["Unknown error"]))
                detail = step2_data.get("systemErrorMessage") or step2_data.get("errorDetailId") or ""
                if "fraudRulesReject" in (step2_data.get("errorIds") or []):
                    detail = "被 SheerID 风控拦截（IP 信誉 / 设备会话）"
                raise Exception(f"步骤 2 错误: {error_msg}" + (f"（{detail}）" if detail else ""))

            logger.info(f"✅ 步骤 2 完成: {step2_data.get('currentStep')}")
            current_step = step2_data.get("currentStep", current_step)

            # 跳过 SSO（如需要）
            if current_step in ["sso", "collectStudentPersonalInfo"]:
                logger.info("步骤 3/4: 跳过 SSO 验证...")
                step3_data, _ = self._sheerid_request(
                    "DELETE",
                    f"{config.SHEERID_BASE_URL}/rest/v2/verification/{self.verification_id}/step/sso",
                )
                logger.info(f"✅ 步骤 3 完成: {step3_data.get('currentStep')}")
                current_step = step3_data.get("currentStep", current_step)

            # 上传文档并完成提交
            logger.info("步骤 4/4: 请求并上传文档...")
            step4_body = {
                "files": [
                    {"fileName": "student_card.png", "mimeType": "image/png", "fileSize": file_size}
                ]
            }
            step4_data, step4_status = self._sheerid_request(
                "POST",
                f"{config.SHEERID_BASE_URL}/rest/v2/verification/{self.verification_id}/step/docUpload",
                step4_body,
            )
            if not step4_data.get("documents"):
                raise Exception("未能获取上传 URL")

            upload_url = step4_data["documents"][0]["uploadUrl"]
            logger.info("✅ 获取上传 URL 成功")
            if not self._upload_to_s3(upload_url, img_data):
                raise Exception("S3 上传失败")
            logger.info("✅ 学生证上传成功")

            step6_data, _ = self._sheerid_request(
                "POST",
                f"{config.SHEERID_BASE_URL}/rest/v2/verification/{self.verification_id}/step/completeDocUpload",
            )
            logger.info(f"✅ 文档提交完成: {step6_data.get('currentStep')}")
            final_status = step6_data

            # 不做状态轮询，直接返回等待审核
            return {
                "success": True,
                "pending": True,
                "message": "文档已提交，等待审核",
                "verification_id": self.verification_id,
                "redirect_url": final_status.get("redirectUrl"),
                "status": final_status,
            }

        except Exception as e:
            logger.error(f"❌ 验证失败: {e}")
            return {"success": False, "message": str(e), "verification_id": self.verification_id}


def main():
    """主函数 - 命令行界面"""
    import sys

    print("=" * 60)
    print("SheerID 学生身份验证工具 (Python版)")
    print("=" * 60)
    print()

    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("请输入 SheerID 验证 URL: ").strip()

    if not url:
        print("❌ 错误: 未提供 URL")
        sys.exit(1)

    verification_id = SheerIDVerifier.parse_verification_id(url)
    if not verification_id:
        print("❌ 错误: 无效的验证 ID 格式")
        sys.exit(1)

    print(f"✅ 解析到验证 ID: {verification_id}")
    print()

    verifier = SheerIDVerifier(verification_id)
    result = verifier.verify()

    print()
    print("=" * 60)
    print("验证结果:")
    print("=" * 60)
    print(f"状态: {'✅ 成功' if result['success'] else '❌ 失败'}")
    print(f"消息: {result['message']}")
    if result.get("redirect_url"):
        print(f"跳转 URL: {result['redirect_url']}")
    print("=" * 60)

    return 0 if result["success"] else 1


if __name__ == "__main__":
    exit(main())
