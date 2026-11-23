import os
import ssl
import socket
import smtplib
import subprocess
import sys
import html
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from email.message import EmailMessage
from email.utils import formatdate

# 需要监控的19个域名
DOMAINS = [
    "www.mxkpay.com",
    "img.mxkpay.com",
    "api.mxkpay.com",
    "www.mxk8us.com",
    "www.mxk8.com",
    "job.mxk8.com",
    "nacos.mxk8.com",
    "business.mxk8.com",
    "api.business.mxk8.com",
    "creator.mxk8.com",
    "api.creator.mxk8.com",
    "cards.mxk8.com",
    "img.mxk8.com",
    "api.mxk8.com",
    "www.mxk8creater.com",
    "user.mxkservice.com",
    "www.mengxiang1688.com",
    "ship.mxk8.com",
    "api.ship.mxk8.com",
]

RECIPIENT = os.getenv("ALERT_EMAIL_TO", "tim@mxk8.com")
ALERT_DAYS = 7
TIMEOUT_SECONDS = 12
REPORT_TIMEZONE = ZoneInfo("America/Los_Angeles")


def get_presented_certificate(host):
    """使用SNI读取服务器当前呈现的证书，即使证书已过期也能读取。"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, 443), timeout=TIMEOUT_SECONDS) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            der_cert = tls.getpeercert(binary_form=True)

    result = subprocess.run(
        [
            "openssl", "x509", "-inform", "DER", "-noout",
            "-enddate", "-subject", "-issuer"
        ],
        input=der_cert,
        capture_output=True,
        check=True,
    )

    fields = {}
    for line in result.stdout.decode("utf-8", errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip()

    if "notAfter" not in fields:
        raise RuntimeError("无法解析证书到期时间")

    expiry = datetime.strptime(
        fields["notAfter"], "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)

    return {
        "expiry": expiry,
        "issuer": fields.get("issuer", "未知"),
        "subject": fields.get("subject", "未知"),
    }


def verify_certificate(host):
    """单独验证证书链和主机名。"""
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=TIMEOUT_SECONDS) as raw:
        with context.wrap_socket(raw, server_hostname=host):
            pass


def check_domain(host, checked_at):
    """返回字段统一使用 host / expiry / days / errors。"""
    item = {
        "host": host,
        "expiry": None,
        "days": None,
        "issuer": None,
        "subject": None,
        "errors": [],
        "expiring_soon": False,
        "expired": False,
        "verification_failed": False,
    }

    try:
        cert = get_presented_certificate(host)
        item["expiry"] = cert["expiry"]
        item["issuer"] = cert["issuer"]
        item["subject"] = cert["subject"]

        seconds_left = (item["expiry"] - checked_at).total_seconds()
        item["days"] = int(seconds_left // 86400)

        if seconds_left <= 0:
            item["expired"] = True
            item["errors"].append("证书已过期")
        elif seconds_left <= ALERT_DAYS * 86400:
            item["expiring_soon"] = True
            item["errors"].append(f"证书将在{ALERT_DAYS}天内到期")

    except Exception as exc:
        item["errors"].append(
            f"证书获取失败：{type(exc).__name__}: {exc}"
        )
        return item

    try:
        verify_certificate(host)
    except Exception as exc:
        # 已过期会导致系统证书验证失败；避免把同一问题重复归类。
        if not item["expired"]:
            item["verification_failed"] = True
            item["errors"].append(
                f"TLS证书链/主机名验证失败：{type(exc).__name__}: {exc}"
            )

    return item


def build_email(alerts, checked_at, test_mode=False):
    """生成简洁HTML邮件及纯文本备用版本。"""
    expiring = [x for x in alerts if x["expiring_soon"]]
    expired = [x for x in alerts if x["expired"]]
    failed = [
        x for x in alerts
        if x["expiry"] is None or x["verification_failed"]
    ]

    local_time = checked_at.astimezone(REPORT_TIMEZONE)
    timestamp = local_time.strftime("%Y-%m-%d %H:%M:%S %Z")

    def render_rows(items, label, color):
        rows = []
        for item in items:
            expiry_text = (
                item["expiry"].strftime("%Y-%m-%d %H:%M UTC")
                if item["expiry"] else "无法获取"
            )
            days_text = (
                f'{item["days"]} 天'
                if item["days"] is not None else "未知"
            )
            reason = "；".join(item["errors"])
            rows.append(f"""
              <tr>
                <td style="padding:12px;border-bottom:1px solid #e8edf3;
                           color:#182230;font-weight:600;">
                  {html.escape(item["host"])}
                </td>
                <td style="padding:12px;border-bottom:1px solid #e8edf3;
                           color:#475467;white-space:nowrap;">
                  {html.escape(expiry_text)}
                </td>
                <td style="padding:12px;border-bottom:1px solid #e8edf3;
                           color:#475467;white-space:nowrap;">
                  {html.escape(days_text)}
                </td>
                <td style="padding:12px;border-bottom:1px solid #e8edf3;
                           color:{color};font-weight:600;">
                  {label}
                  <div style="font-size:11px;font-weight:400;color:#667085;">
                    {html.escape(reason)}
                  </div>
                </td>
              </tr>
            """)
        return "".join(rows)

    def render_section(title, items, label, color, description):
        if not items:
            return ""
        return f"""
          <section style="margin-top:26px;">
            <h2 style="margin:0 0 7px;font-size:17px;color:#182230;">
              {title}（{len(items)}）
            </h2>
            <p style="margin:0 0 12px;color:#667085;font-size:13px;">
              {description}
            </p>
            <div style="border:1px solid #e8edf3;border-radius:9px;overflow:hidden;">
              <table role="presentation" width="100%" cellpadding="0"
                     cellspacing="0" style="border-collapse:collapse;font-size:13px;">
                <thead>
                  <tr style="background:#f7f9fc;text-align:left;">
                    <th style="padding:11px 12px;color:#667085;">域名</th>
                    <th style="padding:11px 12px;color:#667085;">证书到期时间</th>
                    <th style="padding:11px 12px;color:#667085;">剩余时间</th>
                    <th style="padding:11px 12px;color:#667085;">状态</th>
                  </tr>
                </thead>
                <tbody>{render_rows(items, label, color)}</tbody>
              </table>
            </div>
          </section>
        """

    if test_mode:
        title = "[测试邮件] MXK8 SSL证书监控样式预览"
    else:
        title = (
            f"[MXK8 SSL告警] 即将到期{len(expiring)}个"
            f"/已过期{len(expired)}个/检测异常{len(failed)}个"
        )

    banner = ""
    if test_mode:
        banner = """
          <div style="margin-bottom:16px;padding:11px 13px;
                      background:#fff7e6;color:#9a6700;border-radius:7px;
                      font-size:13px;font-weight:600;">
            这是邮件样式测试，下面的域名和日期均为模拟数据，不代表真实检测结果。
          </div>
        """

    html_body = f"""<!doctype html>
<html>
<body style="margin:0;padding:24px 12px;background:#f3f5f8;
             font-family:Arial,'Microsoft YaHei',sans-serif;">
  <div style="max-width:760px;margin:0 auto;background:#fff;
              border:1px solid #e7ebf0;border-radius:13px;overflow:hidden;">
    <header style="padding:24px 28px;background:#17365b;color:#fff;">
      <div style="font-size:11px;letter-spacing:1.2px;color:#c8d8ea;">
        MXK8 · INFRASTRUCTURE MONITORING
      </div>
      <h1 style="margin:9px 0 4px;font-size:23px;">SSL 证书监控提醒</h1>
      <div style="font-size:12px;color:#d8e4f0;">
        DAILY CERTIFICATE REPORT · 19 DOMAINS
      </div>
    </header>
    <main style="padding:24px 28px;">
      {banner}
      <p style="margin:0;color:#344054;font-size:14px;line-height:1.7;">
        本次检查发现以下证书需要关注，请及时处理。
      </p>
      <div style="margin-top:15px;padding:12px 14px;background:#f7f9fc;
                  border-radius:8px;color:#475467;font-size:12px;line-height:1.9;">
        检查时间：{timestamp}<br>
        UTC时间：{checked_at.strftime("%Y-%m-%d %H:%M:%S UTC")}<br>
        监控域名：{len(DOMAINS)} 个<br>
        即将到期：{len(expiring)} 个　
        已过期：{len(expired)} 个　
        检测异常：{len(failed)} 个
      </div>
      {render_section("01 · 即将到期证书", expiring, "即将到期",
                      "#b54708", "以下证书将在未来7天内到期，请尽快安排续期。")}
      {render_section("02 · 已过期证书", expired, "已过期",
                      "#b42318", "以下证书已超过有效期，请优先处理。")}
      {render_section("03 · 检测或验证异常", failed, "检测异常",
                      "#b42318", "以下域名无法获取证书，或证书链/主机名验证失败。")}
      <footer style="margin-top:26px;padding-top:15px;border-top:1px solid #e8edf3;
                     color:#667085;font-size:11px;line-height:1.8;">
        本邮件由 MXK8 SSL 自动监控程序发送。<br>
        证书到期时间以本次连接获取到的服务器证书为准。
      </footer>
    </main>
  </div>
</body>
</html>"""

    plain_lines = [
        "MXK8 SSL证书监控提醒",
        f"检查时间：{timestamp}",
        f"即将到期：{len(expiring)}个；已过期：{len(expired)}个；检测异常：{len(failed)}个",
        "",
    ]
    if test_mode:
        plain_lines.insert(0, "【测试邮件】以下数据为模拟数据，不代表真实检测结果。")

    for section_title, items in [
        ("即将到期证书", expiring),
        ("已过期证书", expired),
        ("检测或验证异常", failed),
    ]:
        if items:
            plain_lines.append(section_title)
            for item in items:
                expiry_text = (
                    item["expiry"].strftime("%Y-%m-%d %H:%M UTC")
                    if item["expiry"] else "无法获取"
                )
                days_text = (
                    str(item["days"]) if item["days"] is not None else "未知"
                )
                plain_lines.append(
                    f'- {item["host"]} | 到期：{expiry_text} | 剩余：{days_text}天'
                )
                for error in item["errors"]:
                    plain_lines.append(f"  原因：{error}")
            plain_lines.append("")

    return title, "\n".join(plain_lines), html_body


def send_email(alerts, checked_at, test_mode=False):
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_user = os.environ["SMTP_USER"]
    smtp_password = os.environ["SMTP_PASSWORD"]
    smtp_from = os.getenv("SMTP_FROM") or smtp_user

    subject, plain_text, html_body = build_email(
        alerts, checked_at, test_mode=test_mode
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_from
    message["To"] = RECIPIENT
    message["Date"] = formatdate(localtime=True)
    message.set_content(plain_text)
    message.add_alternative(html_body, subtype="html")

    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20) as server:
            server.login(smtp_user, smtp_password)
            server.send_message(message)
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            server.login(smtp_user, smtp_password)
            server.send_message(message)


def make_test_alert(checked_at):
    """构造明确标注为模拟数据的邮件样式测试记录。"""
    sample_expiry = checked_at + timedelta(days=3)
    return [{
        "host": "img.mxk8.com（示例）",
        "expiry": sample_expiry,
        "days": 3,
        "issuer": "示例证书颁发机构",
        "subject": "示例证书",
        "errors": ["样式测试：模拟证书将在3天后到期"],
        "expiring_soon": True,
        "expired": False,
        "verification_failed": False,
    }]


def main():
    checked_at = datetime.now(timezone.utc)
    results = [check_domain(host, checked_at) for host in DOMAINS]
    alerts = [item for item in results if item["errors"]]

    print(f"检查时间（UTC）：{checked_at.isoformat()}")
    print(f"域名数量：{len(DOMAINS)}；异常数量：{len(alerts)}")

    for item in results:
        print(
            f"{item['host']} | expiry={item['expiry']} | "
            f"days={item['days']} | errors={item['errors']}"
        )

    if alerts:
        send_email(alerts, checked_at)
        print(f"告警邮件已提交发送，收件人：{RECIPIENT}")
    elif os.getenv("SEND_TEST_EMAIL", "false").lower() == "true":
        send_email(make_test_alert(checked_at), checked_at, test_mode=True)
        print(f"样式测试邮件已提交发送，收件人：{RECIPIENT}")
    else:
        print("所有证书正常且剩余超过7天，不发送邮件。")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            f"监控程序执行失败：{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
