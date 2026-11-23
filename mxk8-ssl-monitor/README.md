# MXK8 SSL/TLS Certificate Monitor

Checks the live HTTPS certificate for all 19 configured domains once per day.

## Alert behavior
- Expires in 7 days or less: email every day.
- Expired: email every day.
- DNS, TCP/443, TLS handshake, certificate retrieval, or CA/hostname verification failure: email every day.
- All healthy with more than 7 days remaining: no email.
- All alert domains are combined into one email to `tim@mxk8.com`.
- Manual workflow runs can optionally send a separate SMTP test email.

## Install
1. Create a **private** GitHub repository, e.g. `mxk8-ssl-monitor`.
2. Upload the contents of this ZIP to the repository root. Preserve `.github/workflows/ssl-monitor.yml`.
3. Open **Settings -> Secrets and variables -> Actions -> New repository secret**.
4. Add these repository secrets:
   - `SMTP_HOST`: your mail provider's SMTP server
   - `SMTP_PORT`: `587` (STARTTLS) or `465` (implicit SSL)
   - `SMTP_USER`: SMTP login username
   - `SMTP_PASSWORD`: SMTP password or provider-issued app password
   - `SMTP_FROM`: verified sender address (optional; defaults to `SMTP_USER`)
5. Open **Actions -> MXK8 SSL Certificate Monitor -> Run workflow**. Set `send_test_email` to `true` for the first run to test delivery to `tim@mxk8.com`.
6. Confirm the run completes and the test message arrives. Then run it again with `send_test_email` set to `false` (or leave it false for normal monitoring).

## Schedule
Daily at 16:15 UTC. This is 08:15 Pacific Standard Time or 09:15 Pacific Daylight Time. GitHub cron uses UTC here, so local time shifts by one hour with daylight saving time. Scheduled workflows run from the default branch; keep the workflow file on that branch.

## Important notes
- SMTP credentials are not included. Add them as GitHub repository secrets; never commit them to the repository.
- The monitor sends no email when all certificates are healthy and more than 7 days remain.
- If SMTP configuration or delivery fails, the workflow fails and the error is visible in GitHub Actions logs. Configure GitHub repository notifications as a secondary alert for workflow failures.
- A connection failure is reported as a detection failure; it is not automatically treated as proof that the certificate is expired.
- GitHub scheduled runs can be delayed during platform load.
