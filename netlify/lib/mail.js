import nodemailer from "nodemailer";

export function mailConfigured() {
  return ["SMTP_HOST", "SMTP_USER", "SMTP_PASS"].every((name) => Netlify.env.get(name));
}

export async function sendMail({ to, subject, text, html }) {
  const port = Number(Netlify.env.get("SMTP_PORT") || 465);
  const user = Netlify.env.get("SMTP_USER");
  const transport = nodemailer.createTransport({
    host: Netlify.env.get("SMTP_HOST"),
    port,
    secure: port === 465,
    auth: { user, pass: Netlify.env.get("SMTP_PASS") },
  });
  // Gmail and Yandex rewrite or reject mail whose From differs from the login.
  await transport.sendMail({ from: `Tastix <${user}>`, to, subject, text, html });
}
