const Brevo = require('@getbrevo/brevo');

// Configure the Brevo client
const brevo = new Brevo.TransactionalEmailsApi();
brevo.setApiKey(
  Brevo.TransactionalEmailsApiApiKeys.apiKey,
  process.env.BREVO_API_KEY
);

async function sendMail({ to, subject, html }) {
  const mailOptions = {
    sender: {
      name: "Admin Advestore (no-reply)",
      email: process.env.EMAIL_USER, // must be verified in Brevo
    },
    to: [{ email: to }],
    subject,
    htmlContent: html,
  };

  try {
    const data = await brevo.sendTransacEmail(mailOptions);
    console.log("✅ Email sent:", data.body);
    return data.body;
  } catch (error) {
    console.error("❌ Error sending email:", error.response?.body || error);
    throw error;
  }
}

module.exports = { sendMail };
