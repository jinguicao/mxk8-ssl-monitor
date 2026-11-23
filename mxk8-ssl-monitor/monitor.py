import os, ssl, socket, smtplib, subprocess, sys
from datetime import datetime, timezone
from email.message import EmailMessage

DOMAINS = [
"www.mxkpay.com","img.mxkpay.com","api.mxkpay.com","www.mxk8us.com",
"www.mxk8.com","job.mxk8.com","nacos.mxk8.com","business.mxk8.com",
"api.business.mxk8.com","creator.mxk8.com","api.creator.mxk8.com",
"cards.mxk8.com","img.mxk8.com","api.mxk8.com","www.mxk8creater.com",
"user.mxkservice.com","www.mengxiang1688.com","ship.mxk8.com","api.ship.mxk8.com"
]
RECIPIENT = os.getenv("ALERT_EMAIL_TO", "tim@mxk8.com")
DAYS_LIMIT = 7

def fetch_cert(host):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=12) as s:
        with ctx.wrap_socket(s, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    p = subprocess.run(["openssl","x509","-inform","DER","-noout","-enddate","-subject","-issuer"],
                       input=der, capture_output=True, check=True)
    vals = {}
    for line in p.stdout.decode(errors="replace").splitlines():
        if "=" in line:
            k,v = line.split("=",1); vals[k.strip()] = v.strip()
    expiry = datetime.strptime(vals["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return expiry, vals.get("issuer","unknown")

def check(host, now):
    item = {"host":host,"expiry":None,"days":None,"issuer":None,"errors":[]}
    try:
        item["expiry"], item["issuer"] = fetch_cert(host)
        seconds = (item["expiry"]-now).total_seconds()
        item["days"] = int(seconds//86400)
        if seconds <= 0: item["errors"].append("证书已过期")
        elif seconds <= DAYS_LIMIT*86400: item["errors"].append("证书将在7天内到期")
    except Exception as e:
        item["errors"].append(f"证书获取失败：{type(e).__name__}: {e}")
        return item
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,443),timeout=12) as s:
            with ctx.wrap_socket(s,server_hostname=host): pass
    except Exception as e:
        item["errors"].append(f"TLS证书链/主机名验证失败：{type(e).__name__}: {e}")
    return item

def send_alert(items, now):
    host=os.environ["SMTP_HOST"]; port=int(os.getenv("SMTP_PORT","587"))
    user=os.environ["SMTP_USER"]; password=os.environ["SMTP_PASSWORD"]
    sender=os.getenv("SMTP_FROM") or user
    lines=["MXK8 SSL/TLS证书监控告警",f"检查时间（UTC）：{now:%Y-%m-%d %H:%M:%S}",f"异常域名：{len(items)}",""]
    for x in items:
        lines += [f"域名：{x['host']}",
                  f"到期时间（UTC）：{x['expiry']:%Y-%m-%d %H:%M:%S}" if x["expiry"] else "到期时间：无法获取",
                  f"剩余天数：{x['days'] if x['days'] is not None else '未知'}"]
        lines += [f"异常：{e}" for e in x["errors"]]
        if x["issuer"]: lines.append(f"颁发机构：{x['issuer']}")
        lines.append("")
    msg=EmailMessage(); msg["Subject"]=f"[MXK8 SSL告警] {len(items)}个域名需要处理"
    msg["From"]=sender; msg["To"]=RECIPIENT; msg.set_content("\n".join(lines))
    if port==465:
        with smtplib.SMTP_SSL(host,port,timeout=20) as s:
            s.login(user,password); s.send_message(msg)
    else:
        with smtplib.SMTP(host,port,timeout=20) as s:
            s.ehlo(); s.starttls(context=ssl.create_default_context()); s.ehlo()
            s.login(user,password); s.send_message(msg)

def send_test_email(now):
    host=os.environ["SMTP_HOST"]; port=int(os.getenv("SMTP_PORT","587"))
    user=os.environ["SMTP_USER"]; password=os.environ["SMTP_PASSWORD"]
    sender=os.getenv("SMTP_FROM") or user
    msg=EmailMessage()
    msg["Subject"]="[MXK8 SSL监控] SMTP邮件发送测试"
    msg["From"]=sender
    msg["To"]=RECIPIENT
    msg.set_content(
        "这是一封 MXK8 SSL证书监控测试邮件。\\n"
        f"测试时间（UTC）：{now:%Y-%m-%d %H:%M:%S}\\n"
        f"收件人配置：{RECIPIENT}\\n"
        "如果收到此邮件，说明 GitHub Actions 到 SMTP 的邮件发送配置基本可用。"
    )
    if port==465:
        with smtplib.SMTP_SSL(host,port,timeout=20) as server:
            server.login(user,password); server.send_message(msg)
    else:
        with smtplib.SMTP(host,port,timeout=20) as server:
            server.ehlo(); server.starttls(context=ssl.create_default_context()); server.ehlo()
            server.login(user,password); server.send_message(msg)

def main():
    now=datetime.now(timezone.utc)
    results=[check(d,now) for d in DOMAINS]
    alerts=[x for x in results if x["errors"]]
    for x in results:
        print(x["host"], "expiry=",x["expiry"],"days=",x["days"],"errors=",x["errors"])
    if alerts:
        send_alert(alerts,now); print("Alert sent to",RECIPIENT)
    elif os.getenv("SEND_TEST_EMAIL","false").lower() == "true":
        send_test_email(now); print("Test email sent to",RECIPIENT)
    else: print("All certificates healthy; no email sent.")

if __name__=="__main__":
    try: main()
    except Exception as e:
        print(f"MONITOR FAILED: {type(e).__name__}: {e}",file=sys.stderr); sys.exit(1)
