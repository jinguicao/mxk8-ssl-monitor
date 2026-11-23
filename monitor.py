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

