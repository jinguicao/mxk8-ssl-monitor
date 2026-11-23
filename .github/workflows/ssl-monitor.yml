
def send_alert(alerts, checked_at):
    import html
    from email.message import EmailMessage

    host = os.environ["SMTP_HOST"]
    port = int(os.getenv("SMTP_PORT", "465"))
    username = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASSWORD"]
    sender = os.getenv("SMTP_FROM") or username

    # 只展示异常域名，正常域名不进入邮件
    expiring = [
        x for x in alerts
        if x["days"] is not None and 0 <= x["days"] <= 7
    ]

    expired = [
        x for x in alerts
        if x["days"] is not None and x["days"] < 0
    ]

    failed = [
        x for x in alerts
        if x["expires"] is None
        or any("验证失败" in e or "获取失败" in e
               for e in x["errors"])
    ]

    def make_rows(items, status, color):
        rows = ""
        for x in items:
            expiry = (
                x["expires"].strftime("%Y-%m-%d %H:%M UTC")
                if x["expires"] else "无法获取"
            )
            days = (
                f'{x["days"]}天'
                if x["days"] is not None else "未知"
            )
            reason = "；".join(x["errors"])

            rows += f"""
            <tr>
              <td style="padding:13px;border-bottom:1px solid #eee;">
                <b>{html.escape(x["domain"])}</b>
              </td>
              <td style="padding:13px;border-bottom:1px solid #eee;">
                {expiry}
              </td>
              <td style="padding:13px;border-bottom:1px solid #eee;">
                {days}
              </td>
              <td style="padding:13px;border-bottom:1px solid #eee;
                         color:{color};font-weight:bold;">
                {status}
                <div style="font-size:11px;font-weight:normal;color:#777;">
                  {html.escape(reason)}
                </div>
              </td>
            </tr>
            """
        return rows

    def make_section(title, items, status, color, description):
        if not items:
            return ""

        return f"""
        <h3 style="margin:26px 0 8px;color:#25364a;">
          {title}（{len(items)}）
        </h3>
        <p style="font-size:13px;color:#777;">{description}</p>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border:1px solid #eee;border-collapse:collapse;
                      font-size:13px;">
          <tr style="background:#f5f7fa;color:#667085;text-align:left;">
            <th style="padding:12px;">域名</th>
            <th style="padding:12px;">到期时间</th>
            <th style="padding:12px;">剩余天数</th>
            <th style="padding:12px;">状态</th>
          </tr>
          {make_rows(items, status, color)}
        </table>
        """

    local_time = checked_at.astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )

    html_body = f"""
    <html>
    <body style="margin:0;padding:20px;background:#f3f5f8;
                 font-family:Arial,'Microsoft YaHei',sans-serif;">

      <div style="max-width:760px;margin:auto;background:#fff;
                  border-radius:10px;overflow:hidden;">

        <div style="background:#17365b;padding:25px 28px;color:white;">
          <div style="font-size:12px;color:#cbd8e8;">
            MXK8 INFRASTRUCTURE MONITORING
          </div>
          <h2 style="margin:10px 0 5px;">
            SSL 证书监控提醒
          </h2>
          <div style="font-size:12px;color:#d5e0ed;">
            DAILY CERTIFICATE REPORT
          </div>
        </div>

        <div style="padding:25px 28px;">

          <p style="color:#475467;font-size:14px;">
            本次检查发现以下证书异常，请及时处理。
          </p>

          <div style="background:#f5f7fa;padding:15px;
                      border-radius:7px;font-size:13px;
                      line-height:2;color:#475467;">
            检查时间：{local_time}<br>
            监控域名：19个<br>
            即将到期：{len(expiring)}个<br>
            已经过期：{len(expired)}个<br>
            检测异常：{len(failed)}个
          </div>

          {make_section(
              "01 · 即将到期证书", expiring,
              "即将到期", "#b54708",
              "以下证书将在7天内到期，请尽快续期。"
          )}

          {make_section(
              "02 · 已过期证书", expired,
              "已过期", "#b42318",
              "以下证书已经超过有效期，请优先处理。"
          )}

          {make_section(
              "03 · 检测异常", failed,
              "检测异常", "#b42318",
              "以下域名无法完成可靠检测或证书验证失败。"
          )}

          <div style="margin-top:28px;padding-top:16px;
                      border-top:1px solid #eee;
                      color:#98a2b3;font-size:11px;line-height:1.8;">
            本邮件由 MXK8 SSL 自动监控系统发送。<br>
            证书到期时间以本次实时检测结果为准。
          </div>

        </div>
      </div>
    </body>
    </html>
    """

    # 同时提供纯文本版本，兼容不支持HTML的邮箱客户端
    plain = [
        "MXK8 SSL证书监控提醒",
        f"检查时间：{local_time}",
        f"即将到期：{len(expiring)}个",
        f"已过期：{len(expired)}个",
        f"检测异常：{len(failed)}个",
        ""
    ]

    for title, items in [
        ("即将到期证书", expiring),
        ("已过期证书", expired),
        ("检测异常", failed)
    ]:
        for x in items:
            plain.append(
                f'{title}：{x["domain"]}，'
                f'到期时间：{x["expires"]}，'
                f'剩余天数：{x["days"]}，'
                f'原因：{"；".join(x["errors"])}'
            )

    message = EmailMessage()
    message["Subject"] = (
        f"[MXK8 SSL告警] 即将到期{len(expiring)}个"
        f"/已过期{len(expired)}个/异常{len(failed)}个"
    )
    message["From"] = sender
    message["To"] = os.getenv(
        "ALERT_EMAIL_TO", "tim@mxk8.com"
    )

    message.set_content("\n".join(plain))
    message.add_alternative(html_body, subtype="html")

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=20) as server:
            server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=20) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(username, password)
            server.send_message(message)
