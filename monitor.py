import os
import ssl
import socket
import smtplib
import subprocess
import sys
import html
import math
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from email.message import EmailMessage
from email.utils import formatdate

DOMAINS = [
    "www.mxkpay.com", "img.mxkpay.com", "api.mxkpay.com",
    "www.mxk8us.com", "www.mxk8.com", "job.mxk8.com",
    "nacos.mxk8.com", "business.mxk8.com", "api.business.mxk8.com",
    "creator.mxk8.com", "api.creator.mxk8.com", "cards.mxk8.com",
    "img.mxk8.com", "api.mxk8.com", "www.mxk8creater.com",
    "user.mxkservice.com", "www.mengxiang1688.com",
    "ship.mxk8.com", "api.ship.mxk8.com",
]

RECIPIENT = os.getenv("ALERT_EMAIL_TO", "tim@mxk8.com")
ALERT_DAYS = 7
TIMEOUT = 12
BEIJING = ZoneInfo("Asia/Shanghai")


def get_certificate(host):
    """通过SNI读取服务器当前呈现的证书。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)

    p = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout",
         "-enddate", "-issuer"],
        input=der, capture_output=True, check=True
    )

    fields = {}
    for line in p.stdout.decode("utf-8", errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()

    if "notAfter" not in fields:
        raise RuntimeError("无法解析证书到期时间")

    expiry = datetime.strptime(
        fields["notAfter"], "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)

    return expiry, fields.get("issuer", "未知")


def verify_certificate(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=host):
            pass


def check_domain(host, now):
    item = {
        "host": host,
        "expiry": None,
        "days": None,
        "issuer": None,
        "expired": False,
        "soon": False,
        "errors": [],
    }

    try:
        item["expiry"], item["issuer"] = get_certificate(host)
        seconds = (item["expiry"] - now).total_seconds()

        if seconds <= 0:
            item["expired"] = True
            return item

        item["days"] = math.ceil(seconds / 86400)
        item["soon"] = seconds <= ALERT_DAYS * 86400

    except Exception as exc:
        item["errors"].append(
            f"证书获取失败：{type(exc).__name__}: {exc}"
        )
        return item

    try:
        verify_certificate(host)
    except Exception as exc:
        item["errors"].append(
            f"TLS证书链/主机名验证失败：{type(exc).__name__}: {exc}"
        )

    return item


def build_email(results, now):
    # 只显示成功获取且尚未过期的证书
    valid = [
        x for x in results
        if x["expiry"] and not x["expired"]
    ]
    valid.sort(key=lambda x: x["expiry"])

    # 已过期证书不展示
    failures = [
        x for x in results
        if not x["expired"] and x["errors"]
    ]

    soon_count = sum(x["soon"] for x in valid)
    local_time = now.astimezone(BEIJING)
    time_text = local_time.strftime("%Y-%m-%d %H:%M:%S 北京时间")

    def cert_rows():
        out = []

        for x in valid:
            exp = x["expiry"].astimezone(BEIJING).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            if x["soon"]:
                status = "7天内到期"
                fg = "#9a6700"
                bg = "#fff4e5"
            elif x["errors"]:
                status = "验证异常"
                fg = "#b42318"
                bg = "#fff0ee"
            else:
                status = "正常"
                fg = "#067647"
                bg = "#ecfdf3"

            out.append(f"""
            <tr>
              <td style="padding:12px;border-bottom:1px solid #e8edf3;font-weight:600;">
                {html.escape(x['host'])}
              </td>
              <td style="padding:12px;border-bottom:1px solid #e8edf3;">
                {exp}
              </td>
              <td style="padding:12px;border-bottom:1px solid #e8edf3;">
                {x['days']}天
              </td>
              <td style="padding:12px;border-bottom:1px solid #e8edf3;">
                <span style="padding:4px 8px;border-radius:5px;background:{bg};color:{fg};">
                  {status}
                </span>
              </td>
            </tr>
            """)

        return "".join(out)

    def failure_rows():
        return "".join(
            f"""<tr>
              <td style="padding:12px;border-bottom:1px solid #e8edf3;font-weight:600;">
                {html.escape(x['host'])}
              </td>
              <td style="padding:12px;border-bottom:1px solid #e8edf3;color:#b42318;">
                {html.escape('；'.join(x['errors']))}
              </td>
            </tr>"""
            for x in failures
        )

    if valid:
        valid_section = f"""
        <h2 style="font-size:17px;color:#182230;margin:26px 0 8px;">
          未过期证书列表（{len(valid)}）
        </h2>
        <p style="font-size:13px;color:#667085;">
          展示所有成功获取且尚未过期的证书，按到期时间排序。
          7天内到期的证书会特别标记。
        </p>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse;font-size:13px;border:1px solid #e8edf3;">
          <thead>
            <tr style="background:#f7f9fc;text-align:left;">
              <th style="padding:11px;">域名</th>
              <th style="padding:11px;">过期时间（北京时间）</th>
              <th style="padding:11px;">剩余天数</th>
              <th style="padding:11px;">状态</th>
            </tr>
          </thead>
          <tbody>{cert_rows()}</tbody>
        </table>
        """
    else:
        valid_section = """
        <p style="padding:14px;background:#f7f9fc;border-radius:8px;color:#667085;">
          本次没有检测到可展示的未过期证书。
        </p>
        """

    failure_section = ""

    if failures:
        failure_section = f"""
        <h2 style="font-size:17px;color:#b42318;margin:26px 0 8px;">
          检测异常（{len(failures)}）
        </h2>
        <p style="font-size:13px;color:#667085;">
          以下域名无法获取证书，或证书链/主机名验证失败。
        </p>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse;font-size:13px;border:1px solid #e8edf3;">
          <thead>
            <tr style="background:#fff5f4;text-align:left;">
              <th style="padding:11px;">域名</th>
              <th style="padding:11px;">错误原因</th>
            </tr>
          </thead>
          <tbody>{failure_rows()}</tbody>
        </table>
        """

    subject = (
        f"[MXK8 SSL监控] 未过期证书{len(valid)}个"
        f"/7天内到期{soon_count}个/检测异常{len(failures)}个"
    )

    body = f"""<!doctype html>
<html>
<body style="margin:0;padding:24px 12px;background:#f3f5f8;
font-family:Arial,'Microsoft YaHei',sans-serif;">

<div style="max-width:820px;margin:auto;background:#fff;
border:1px solid #e7ebf0;border-radius:13px;overflow:hidden;">

<header style="padding:24px 28px;background:#17365b;color:#fff;">
<div style="font-size:11px;letter-spacing:1.2px;color:#c8d8ea;">
MXK8 · INFRASTRUCTURE MONITORING
</div>
<h1 style="margin:9px 0 4px;font-size:23px;">
SSL证书监控报告
</h1>
<div style="font-size:12px;color:#d8e4f0;">
DAILY CERTIFICATE STATUS · 19 DOMAINS
</div>
</header>

<main style="padding:24px 28px;">

<p style="font-size:14px;color:#344054;">
本次已完成19个域名的HTTPS证书检查，
以下列出全部未过期证书及其过期时间。
</p>

<div style="padding:13px 15px;background:#f7f9fc;
border-radius:8px;color:#475467;font-size:12px;line-height:1.9;">
检查时间：{time_text}<br>
监控域名：{len(DOMAINS)}个<br>
未过期证书：{len(valid)}个<br>
7天内到期：{soon_count}个<br>
检测异常：{len(failures)}个
</div>

{valid_section}
{failure_section}

<footer style="margin-top:27px;padding-top:16px;
border-top:1px solid #e8edf3;color:#667085;
font-size:11px;line-height:1.8;">
本邮件由MXK8 SSL自动监控程序发送。<br>
证书过期时间以本次连接从服务器获取的证书为准。
已过期证书不在本报告中展示。
</footer>

</main>
</div>
</body>
</html>"""

    plain = [
        "MXK8 SSL证书监控报告",
        f"检查时间：{time_text}",
        f"未过期证书：{len(valid)}个",
        f"7天内到期：{soon_count}个",
        f"检测异常：{len(failures)}个",
        "",
        "未过期证书列表：",
    ]

    for x in valid:
        exp = x["expiry"].astimezone(BEIJING).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        status = (
            "7天内到期" if x["soon"]
            else ("验证异常" if x["errors"] else "正常")
        )
        plain.append(
            f"- {x['host']} | 过期时间：{exp} 北京时间 | "
            f"剩余：{x['days']}天 | 状态：{status}"
        )

    if failures:
        plain.extend(["", "检测异常："])
        for x in failures:
            plain.append(
                f"- {x['host']} | {'；'.join(x['errors'])}"
            )

    return subject, "\n".join(plain), body


def send_email(results, now):
    host = os.environ["SMTP_HOST"]
    port = int(os.getenv("SMTP_PORT", "465"))
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASSWORD"]
    sender = os.getenv("SMTP_FROM") or user

    subject, plain, body = build_email(results, now)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = RECIPIENT
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(plain)
    msg.add_alternative(body, subtype="html")

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=20) as server:
            server.login(user, password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            server.login(user, password)
            server.send_message(msg)


def main():
    now = datetime.now(timezone.utc)
    results = [check_domain(host, now) for host in DOMAINS]

    print(
        "检查时间（北京时间）：",
        now.astimezone(BEIJING).isoformat()
    )

    for x in results:
        print(
            f"{x['host']} | expiry={x['expiry']} | "
            f"days={x['days']} | expired={x['expired']} | "
            f"errors={x['errors']}"
        )

    # 每次定时运行都发送报告。
    # 展示所有未过期证书；已过期证书不展示。
    send_email(results, now)
    print(f"报告已发送至 {RECIPIENT}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            f"监控程序执行失败：{type(exc).__name__}: {exc}",
            file=sys.stderr
        )
        sys.exit(1)
