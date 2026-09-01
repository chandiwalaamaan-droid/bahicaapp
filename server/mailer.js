const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
});

async function sendOtp(email, code) {
  const from = process.env.MAIL_FROM || 'Tally <no-reply@example.com>';
  const subject = 'Your Tally login code';
  const text = `Your Tally verification code is: ${code}\n\nThis code expires in 15 minutes. If you didn't request it, ignore this email.`;
  const html = `<div style="font-family:Inter,system-ui,sans-serif;max-width:480px;margin:0 auto;padding:24px">
    <h2 style="margin:0 0 16px">Your Tally login code</h2>
    <p style="font-size:32px;font-weight:700;letter-spacing:6px;margin:16px 0;color:#E2A54D">${code}</p>
    <p style="color:#666">This code expires in 15 minutes. If you didn't request it, you can safely ignore this email.</p>
  </div>`;
  await transporter.sendMail({ from, to: email, subject, text, html });
}

module.exports = { sendOtp };