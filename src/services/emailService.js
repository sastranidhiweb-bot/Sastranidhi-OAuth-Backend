// src/services/emailService.js
//
// Thin abstraction so the rest of the codebase just calls
// emailService.send({ to, subject, text }) without caring whether that
// actually hits SMTP or not.
//
// DEV (default, env.email.transport === 'console'): logs the email via the
// existing logger instead of sending it. This is how you'll actually see
// verification codes and reset links while testing locally — check the
// server console/logs, not an inbox.
//
// PROD (env.email.transport === 'smtp'): requires the `nodemailer` package
// (NOT currently in package.json — `npm install nodemailer` before
// switching EMAIL_TRANSPORT=smtp) plus SMTP_HOST/PORT/USER/PASSWORD and
// EMAIL_FROM in .env. This module intentionally doesn't `require`
// nodemailer at the top level, so the server still boots fine in dev
// without that dependency installed at all.
//
// Never log the raw password-reset token or verification code anywhere
// except this dev transport's own output, and never include either in an
// audit_logs row — both are treated the same as a password in that
// respect.

const logger = require('../config/logger');
const env = require('../config/env');

async function sendConsole({ to, subject, text }) {
  logger.info('[emailService] DEV MODE — email not actually sent, logging instead', {
    to,
    subject,
    body: text,
  });
}

let smtpTransporter = null;

async function sendSmtp({ to, subject, text }) {
  if (!smtpTransporter) {
    let nodemailer;
    try {
      // eslint-disable-next-line global-require
      nodemailer = require('nodemailer');
    } catch {
      throw new Error(
        "EMAIL_TRANSPORT=smtp requires the 'nodemailer' package — run `npm install nodemailer`."
      );
    }

    if (!env.email.smtp.host || !env.email.smtp.user || !env.email.smtp.password) {
      throw new Error(
        'EMAIL_TRANSPORT=smtp requires SMTP_HOST, SMTP_USER and SMTP_PASSWORD to be set in .env.'
      );
    }

    smtpTransporter = nodemailer.createTransport({
      host: env.email.smtp.host,
      port: env.email.smtp.port,
      secure: env.email.smtp.secure,
      auth: { user: env.email.smtp.user, pass: env.email.smtp.password },
    });
  }

  await smtpTransporter.sendMail({ from: env.email.from, to, subject, text });
}

async function send({ to, subject, text }) {
  if (env.email.transport === 'smtp') {
    return sendSmtp({ to, subject, text });
  }
  return sendConsole({ to, subject, text });
}

module.exports = { send };
