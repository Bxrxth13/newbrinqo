require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const xss = require('xss');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

app.post('/send-form', formLimiter, async (req, res) => {
  try {
    const { name, email, phone, message, _honeypot } = req.body;

    // Basic Spam Protection (Honeypot)
    if (_honeypot) {
      // If honeypot is filled out, pretend it was successful (but do nothing)
      return res.status(200).json({ success: true, message: 'Message sent successfully.' });
    }

    if (!name || !email || !message) {
      return res.status(400).json({ error: 'Name, email, and message are required fields.' });
    }

    // Sanitize input
    const cleanName = xss(name);
    const cleanEmail = xss(email);
    const cleanPhone = phone ? xss(phone) : 'N/A';
    const cleanMessage = xss(message);

    // Admin Email HTML
    const adminHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">New Contact Form Submission</h2>
        <table style="width: 100%; border-collapse: collapse;">
          <tr style="background-color: #f8f9fa;">
            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; width: 30%;">Name</th>
            <td style="padding: 10px; border: 1px solid #ddd;">${cleanName}</td>
          </tr>
          <tr>
            <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Email</th>
            <td style="padding: 10px; border: 1px solid #ddd;">
              <a href="mailto:${cleanEmail}">${cleanEmail}</a>
            </td>
          </tr>
          <tr style="background-color: #f8f9fa;">
            <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Phone</th>
            <td style="padding: 10px; border: 1px solid #ddd;">${cleanPhone}</td>
          </tr>
          <tr>
            <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Message</th>
            <td style="padding: 10px; border: 1px solid #ddd; white-space: pre-wrap;">${cleanMessage}</td>
          </tr>
        </table>
      </div>
    `;

    // User Auto-Reply Email HTML
    const userHtml = `
      <div style="font-family: 'Space Grotesk', Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #1e1e1e;">
        <h2>Thank You for Contacting Brinqo</h2>
        <p>Hello ${cleanName},</p>
        <p>Congratulations 🎉 and thank you for reaching out to Brinqo.</p>
        <p>We have successfully received your request.</p>
        <p>Our team will contact you within 24 hours.</p>
        <br>
        <p>Best Regards,<br>
        <strong>Team Brinqo</strong><br>
        <a href="https://www.brinqo.com" style="color: #ff4a17;">www.brinqo.com</a></p>
      </div>
    `;

    // Send Admin Notification
    await transporter.sendMail({
      from: '"Brinqo Forms" <noreply@brinqo.com>',
      to: process.env.ADMIN_EMAIL,
      subject: 'New Form Submission — Brinqo',
      html: adminHtml,
      replyTo: cleanEmail,
    });

    // Send User Auto Reply
    await transporter.sendMail({
      from: '"Team Brinqo" <noreply@brinqo.com>',
      to: cleanEmail,
      subject: 'Thank You for Contacting Brinqo',
      html: userHtml,
    });

    res.status(200).json({ success: true, message: 'Message sent successfully.' });

  } catch (error) {
    console.error('Email send error:', error);
    res.status(500).json({ error: 'An error occurred while sending the message. Please try again later.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
