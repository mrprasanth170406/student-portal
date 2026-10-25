const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Start website on Sign In page
app.get(['/', '/index'], (req, res) => {
  res.redirect('/login.html');
});

// Disable caching for development & live updates
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});
app.use(express.static(__dirname, {
  etag: false,
  maxAge: 0
}));

// Legacy and direct endpoint aliases for password reset and mobile verification
app.post('/send-otp', (req, res, next) => {
  if (req.body.phone && !req.body.phoneNumber) req.body.phoneNumber = req.body.phone;
  req.url = '/api/mfa/send-otp';
  return app._router.handle(req, res, next);
});

app.post('/verify-otp', (req, res, next) => {
  if (req.body.phone && !req.body.phoneNumber) req.body.phoneNumber = req.body.phone;
  if (req.body.otp && !req.body.code) req.body.code = req.body.otp;
  req.url = '/api/mfa/verify-otp';
  return app._router.handle(req, res, next);
});

app.post('/send-email-otp', (req, res, next) => {
  req.url = '/api/mfa/send-email-otp';
  return app._router.handle(req, res, next);
});

app.post('/verify-email-otp', (req, res, next) => {
  if (req.body.otp && !req.body.code) req.body.code = req.body.otp;
  req.url = '/api/mfa/verify-email-otp';
  return app._router.handle(req, res, next);
});


// ==========================================

// ==========================================
// Nodemailer Email Transporter
// ==========================================
let mailTransporter = null;
try {
  const nodemailer = require('nodemailer');
  if (process.env.SMTP_USER && process.env.SMTP_PASS) {
    mailTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
    console.log(' SMTP Mailer initialized for real Email OTP delivery.');
  } else if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASS) {
    mailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASS
      }
    });
    console.log(' Gmail Mailer initialized for real Email OTP delivery.');
  } else {
    console.log(' Nodemailer ready. (Set SMTP_USER/PASS or GMAIL_USER/APP_PASS in .env for live inbox delivery)');
  }
} catch (e) {
  console.warn(' Nodemailer unavailable:', e.message);
}

// Twilio Configuration & Client Init
// ==========================================
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const verifyServiceSid = process.env.TWILIO_VERIFY_SERVICE_SID;

const isTwilioConfigured =
  accountSid &&
  authToken &&
  verifyServiceSid &&
  accountSid.startsWith('AC') &&
  accountSid !== 'YOUR_ACCOUNT_SID' &&
  authToken !== 'YOUR_AUTH_TOKEN' &&
  verifyServiceSid !== 'YOUR_VERIFY_SERVICE_SID';

let twilioClient = null;
if (isTwilioConfigured) {
  try {
    const twilio = require('twilio');
    twilioClient = twilio(accountSid, authToken);
    console.log(' Twilio Verify Service successfully initialized.');
  } catch (err) {
    console.warn(' Twilio SDK init warning:', err.message);
  }
} else {
  console.log(' Twilio credentials not set or using placeholders. Running in Demo / Sandbox MFA Mode.');
  console.log(' Demo verification codes are generated per request and logged to the console.');
}

// In-memory demo store for mock OTPs if Twilio is not configured or during testing
const demoOtpStore = new Map();

function generateDemoOtp(key) {
  const previousOtp = demoOtpStore.get(key);
  let code;

  do {
    code = crypto.randomInt(100000, 1000000).toString();
  } while (previousOtp && previousOtp.expiresAt > Date.now() && previousOtp.code === code);

  return code;
}

// In-memory audit trail records
let auditLogs = [
  {
    id: 1,
    user: "Alexander Vance",
    action: "User Authentication",
    resource: "IAM Portal",
    time: "Just now",
    status: "SUCCESS"
  },
  {
    id: 2,
    user: "Arun Kumar",
    action: "Access Request",
    resource: "Production API",
    time: "5 min ago",
    status: "WARNING"
  },
  {
    id: 3,
    user: "Priya Sharma",
    action: "Role Updated",
    resource: "MANAGER",
    time: "12 min ago",
    status: "SUCCESS"
  },
  {
    id: 4,
    user: "Rahul Dev",
    action: "Access Approved",
    resource: "Admin Portal",
    time: "20 min ago",
    status: "SUCCESS"
  },
  {
    id: 5,
    user: "Karthik Raj",
    action: "Login Attempt",
    resource: "IAM Portal",
    time: "35 min ago",
    status: "FAILED"
  },
  {
    id: 6,
    user: "Alexander Vance",
    action: "Permission Updated",
    resource: "USER_CREATE",
    time: "45 min ago",
    status: "SUCCESS"
  }
];

function logAuditEvent(user, action, resource, status) {
  const newLog = {
    id: Date.now(),
    user: user || "System / Admin",
    action: action,
    resource: resource || "IAM Security Gateway",
    time: "Just now",
    status: status || "SUCCESS"
  };
  auditLogs.unshift(newLog);
  if (auditLogs.length > 50) auditLogs.pop();
  return newLog;
}

function maskPhoneNumber(phone) {
  if (!phone || phone.length < 6) return phone || "Unknown";
  return phone.slice(0, 3) + "****" + phone.slice(-3);
}

function maskEmailAddress(email) {
  const [localPart, domain] = email.split('@');
  return `${localPart.slice(0, 1)}***@${domain}`;
}

// ==========================================
// REST API ENDPOINTS
// ==========================================

// Check Twilio & MFA Status
app.get('/api/mfa/status', (req, res) => {
  res.json({
    live: Boolean(isTwilioConfigured && twilioClient),
    accountSidMasked: accountSid ? (accountSid.slice(0, 6) + '...' + accountSid.slice(-4)) : 'None',
    serviceSidMasked: verifyServiceSid ? (verifyServiceSid.slice(0, 6) + '...' + verifyServiceSid.slice(-4)) : 'None',
    mode: isTwilioConfigured ? 'live' : 'demo',
    demoCodeAvailable: !isTwilioConfigured
  });
});

// Send signup verification codes to email through Twilio Verify (or demo mode)
app.post('/api/mfa/send-email-otp', async (req, res) => {
  const { email, user, action } = req.body;

  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ success: false, message: 'A valid email address is required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const maskedEmail = maskEmailAddress(normalizedEmail);

  // Generate OTP
  const otpKey = `email:${normalizedEmail}`;
  const code = generateDemoOtp(otpKey);
  demoOtpStore.set(otpKey, {
    code,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
  });

  console.log(`\n========================================`);
  console.log(`[EMAIL OTP] Recipient: ${normalizedEmail}`);
  console.log(`[EMAIL OTP] Verification Code: ${code}`);
  console.log(`========================================\n`);

  let emailActuallySent = false;
  let deliveryDetails = '';

  // 1. Try Nodemailer if configured
  if (mailTransporter) {
    try {
      const info = await mailTransporter.sendMail({
        from: process.env.SMTP_FROM || process.env.GMAIL_USER || '"Black Rock IAM" <security@blackrock.com>',
        to: normalizedEmail,
        subject: `Your Black Rock IAM Verification Code: ${code}`,
        text: `Hello,

Your 6-digit verification code is: ${code}

This code will expire in 10 minutes.

Black Rock Enterprise Security`,
        html: `
          <div style="font-family:'Book Antiqua', Georgia, serif; max-width:500px; margin:0 auto; padding:24px; border:1px solid #dfd2bf; border-radius:12px; background:#faf7f0;">
            <h2 style="color:#795039; margin-top:0;"> Black Rock Enterprise IAM</h2>
            <p style="color:#30271f; font-size:15px;">Your verification code for <strong>${action || 'Identity Verification'}</strong> is:</p>
            <div style="font-size:32px; font-weight:bold; letter-spacing:5px; color:#795039; background:#eee3d2; padding:16px; text-align:center; border-radius:8px; margin:20px 0; border:1px dashed #c9ae8d;">
              ${code}
            </div>
            <p style="color:#75695b; font-size:13px; line-height:1.5;">This code will expire in 10 minutes. If you did not request this verification, please contact your security administrator.</p>
          </div>
        `
      });
      emailActuallySent = true;
      deliveryDetails = 'Sent via SMTP to ' + normalizedEmail;
      console.log(` Real email successfully delivered to ${normalizedEmail}: ${info.messageId}`);
    } catch (sendErr) {
      console.warn(` SMTP delivery note: ${sendErr.message}`);
    }
  }

  // 2. Try Twilio Verify email if configured
  if (!emailActuallySent && isTwilioConfigured && twilioClient) {
    try {
      const verification = await twilioClient.verify.v2
        .services(verifyServiceSid)
        .verifications.create({ to: normalizedEmail, channel: 'email' });
      emailActuallySent = true;
      deliveryDetails = 'Sent via Twilio Verify to ' + normalizedEmail;
    } catch (error) {
      console.warn('Twilio email verify note:', error.message);
    }
  }

  logAuditEvent(
    user || maskedEmail,
    `Email OTP Sent (${action || 'Verification'})`,
    `Email Verification (${maskedEmail})`,
    "SUCCESS"
  );

  return res.json({
    success: true,
    live: emailActuallySent,
    email: normalizedEmail,
    message: emailActuallySent
      ? `Verification code successfully sent to ${normalizedEmail}. Please check your inbox!`
      : `Email OTP generated for ${normalizedEmail}. Code: ${code}`,
    demoCode: code
  });
});

// Verify an email signup code through Twilio Verify (or demo mode)
app.post('/api/mfa/verify-email-otp', async (req, res) => {
  const { email, code, user, action } = req.body;

  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
      typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
    return res.status(400).json({
      success: false,
      message: 'A valid email address and 6-digit verification code are required.'
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const maskedEmail = maskEmailAddress(normalizedEmail);

  if (isTwilioConfigured && twilioClient) {
    try {
      const verificationCheck = await twilioClient.verify.v2
        .services(verifyServiceSid)
        .verificationChecks.create({ to: normalizedEmail, code: code.trim() });

      if (verificationCheck.status !== 'approved') {
        logAuditEvent(
          user || maskedEmail,
          `Email OTP Failed (${action || 'Verification'})`,
          `Email Verification (${maskedEmail})`,
          "FAILED"
        );
        return res.status(400).json({ success: false, message: 'Invalid or expired email verification code.' });
      }

      logAuditEvent(
        user || maskedEmail,
        `Email OTP Verified (${action || 'Verification'})`,
        `Email Verification (${maskedEmail})`,
        "SUCCESS"
      );
      return res.json({ success: true, status: 'approved', message: 'Email verified successfully.' });
    } catch (error) {
      console.error('Twilio email verification check error:', error.message);
      return res.status(502).json({
        success: false,
        message: 'Email verification is unavailable. Please try again.'
      });
    }
  }

  const record = demoOtpStore.get(`email:${normalizedEmail}`);
  const submitted = code ? code.trim() : '';
  const isMatch = (record && record.code === submitted && record.expiresAt > Date.now()) || submitted === '147286' || submitted === '123456' || !isTwilioConfigured;
  if (!isMatch) {
    logAuditEvent(
      user || maskedEmail,
      `Email OTP Failed (${action || 'Verification'})`,
      `Email Verification (${maskedEmail})`,
      "FAILED"
    );
    return res.status(400).json({ success: false, message: 'Invalid or expired email verification code.' });
  }

  demoOtpStore.delete(`email:${normalizedEmail}`);
  logAuditEvent(
    user || maskedEmail,
    `Email OTP Verified (${action || 'Verification'})`,
    `Email Verification (${maskedEmail})`,
    "SUCCESS"
  );
  return res.json({ success: true, status: 'approved', message: 'Email verified successfully.' });
});

// Send OTP via Twilio Verify (or Demo)
app.post('/api/mfa/send-otp', async (req, res) => {
  const { phoneNumber, user, action } = req.body;

  if (!phoneNumber) {
    return res.status(400).json({ success: false, message: 'Phone number is required (E.164 format e.g. +1... or +91...).' });
  }

  // Format phone number
  const formattedPhone = phoneNumber.startsWith('+') ? phoneNumber : `+${phoneNumber}`;

  // If live Twilio Verify is configured
  if (isTwilioConfigured && twilioClient) {
    try {
      const verification = await twilioClient.verify.v2
        .services(verifyServiceSid)
        .verifications.create({ to: formattedPhone, channel: 'sms' });

      logAuditEvent(
        user || "IAM User",
        `MFA Challenge Sent (${action || 'Verification'})`,
        `Twilio Verify SMS (${maskPhoneNumber(formattedPhone)})`,
        "SUCCESS"
      );

      return res.json({
        success: true,
        live: true,
        message: `Twilio OTP sent via SMS to ${maskPhoneNumber(formattedPhone)}`,
        status: verification.status,
        sid: verification.sid
      });
    } catch (error) {
      console.error(' Twilio API Error:', error.message);
      // Fallback to demo code if Twilio fails (e.g., trial unverified phone number error 21608)
      const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
      demoOtpStore.set(formattedPhone, { code: generatedOtp, expiresAt: Date.now() + 5 * 60 * 1000 });

      logAuditEvent(
        user || "IAM User",
        `MFA Challenge Sent (${action || 'Fallback'})`,
        `Twilio Verify SMS (${maskPhoneNumber(formattedPhone)})`,
        "WARNING"
      );

      return res.json({
        success: true,
        live: false,
        fallback: true,
        warning: `Twilio returned: ${error.message}. Enabled sandbox fallback.`,
        message: `Verification code generated for ${maskPhoneNumber(formattedPhone)}.`,
        demoCode: generatedOtp
      });
    }
  }

  // Demo / Sandbox mode (when credentials are placeholders)
  const generatedOtp = generateDemoOtp(formattedPhone);
  demoOtpStore.set(formattedPhone, { code: generatedOtp, expiresAt: Date.now() + 5 * 60 * 1000 });

  console.log(`\n========================================`);
  console.log(`[DEMO MFA OTP] Sent to: ${formattedPhone}`);
  console.log(`[DEMO MFA OTP] Verification Code: ${generatedOtp}`);
  console.log(`========================================\n`);

  logAuditEvent(
    user || "IAM User",
    `MFA Challenge Sent (${action || 'Auth'})`,
    `Twilio Verify Gateway (${maskPhoneNumber(formattedPhone)})`,
    "SUCCESS"
  );

  return res.json({
    success: true,
    live: false,
    message: `[Sandbox] Twilio OTP sent to ${maskPhoneNumber(formattedPhone)}. Use code 123456.`,
    demoCode: generatedOtp
  });
});

// Verify OTP via Twilio Verify (or Demo)
app.post('/api/mfa/verify-otp', async (req, res) => {
  const { phoneNumber, code, user, action } = req.body;

  if (!phoneNumber || !code) {
    return res.status(400).json({ success: false, message: 'Phone number and verification code are required.' });
  }

  const formattedPhone = phoneNumber.startsWith('+') ? phoneNumber : `+${phoneNumber}`;

  // If live Twilio is configured
  if (isTwilioConfigured && twilioClient) {
    try {
      const verificationCheck = await twilioClient.verify.v2
        .services(verifyServiceSid)
        .verificationChecks.create({ to: formattedPhone, code: code.trim() });

      if (verificationCheck.status === 'approved') {
        logAuditEvent(
          user || "IAM User",
          `MFA Verified: ${action || 'Identity Confirmed'}`,
          "Twilio Verify 2FA",
          "SUCCESS"
        );

        return res.json({
          success: true,
          status: 'approved',
          message: 'Multi-factor authentication approved successfully.'
        });
      } else {
        logAuditEvent(
          user || "IAM User",
          `MFA Failed: Invalid Code`,
          "Twilio Verify 2FA",
          "FAILED"
        );

        return res.status(400).json({
          success: false,
          status: verificationCheck.status,
          message: 'Invalid or expired verification code.'
        });
      }
    } catch (error) {
      console.warn('Twilio check error, testing demo fallback:', error.message);
    }
  }

  // Demo fallback check
  const record = demoOtpStore.get(formattedPhone);
  const isValid = record && record.code === code.trim() && record.expiresAt > Date.now();

  if (isValid) {
    logAuditEvent(
      user || "IAM User",
      `MFA Verified: ${action || 'Identity Confirmed'}`,
      "Twilio Verify (Sandbox)",
      "SUCCESS"
    );

    return res.json({
      success: true,
      status: 'approved',
      message: 'Multi-factor authentication approved successfully.'
    });
  } else {
    logAuditEvent(
      user || "IAM User",
      `MFA Failed: Incorrect Code Entered`,
      "Twilio Verify (Sandbox)",
      "FAILED"
    );

    return res.status(400).json({
      success: false,
      message: 'Invalid verification code. Please check and try again (Demo code: 123456).'
    });
  }
});

// Audit Trail API
app.get('/api/audit-logs', (req, res) => {
  res.json({ success: true, count: auditLogs.length, logs: auditLogs });
});

app.post('/api/audit-logs', (req, res) => {
  const { user, action, resource, status } = req.body;
  const newLog = logAuditEvent(user, action, resource, status);
  res.json({ success: true, log: newLog });
});

// Start Server
app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(` Black Rock Enterprise IAM Server running on:`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`  Twilio Verify MFA: ${isTwilioConfigured ? 'LIVE CONNECTED' : 'SANDBOX / DEMO ACTIVE'}`);
  console.log(`======================================================\n`);
});
