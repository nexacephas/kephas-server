import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import sanitizeHtml from 'sanitize-html';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';
import { Resend } from 'resend';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();

const app = express();
const serverDirectory = path.dirname(fileURLToPath(import.meta.url));
const clientBuildDirectory = path.resolve(serverDirectory, '../dist');
const PORT = Number(process.env.PORT || 5000);
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@kephas.example';
const JWT_SECRET = process.env.JWT_SECRET || 'kephas-dev-secret';
const MAX_REGISTRATIONS = 50;

const memoryRegistrations = [];
let databaseReady = false;
let Registration;
let RegistrationCapacity;

const appLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
  max: Number(process.env.RATE_LIMIT_MAX || 100),
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests. Please wait a moment and try again.' }
});

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(cors({ origin: CLIENT_URL, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use('/api', appLimiter);

function sanitizeText(value) {
  if (typeof value !== 'string') return value;
  return sanitizeHtml(value.trim(), {
    allowedTags: [],
    allowedAttributes: {}
  }).replace(/&amp;/g, '&');
}

function sanitizePayload(data) {
  if (Array.isArray(data)) {
    return data.map((item) => sanitizePayload(item));
  }

  if (data && typeof data === 'object') {
    const clean = {};
    Object.entries(data).forEach(([key, value]) => {
      clean[key] = sanitizePayload(value);
    });
    return clean;
  }

  return typeof data === 'string' ? sanitizeText(data) : data;
}

function parseAgeFromDob(dateString) {
  if (!dateString) return null;
  const birthDate = new Date(dateString);
  if (Number.isNaN(birthDate.getTime())) return null;
  const today = new Date();
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDifference = today.getMonth() - birthDate.getMonth();

  if (monthDifference < 0 || (monthDifference === 0 && today.getDate() < birthDate.getDate())) {
    age -= 1;
  }

  return age;
}

function generateReference() {
  const randomPart = randomUUID().split('-').slice(0, 3).join('').toUpperCase();
  return `KB-${Date.now().toString().slice(-6)}-${randomPart}`;
}

function normalizeDuplicateKey(value) {
  return (value || '').toString().trim().toLowerCase();
}

const registrationSchema = new mongoose.Schema(
  {
    reference: { type: String, required: true, unique: true },
    parentFullName: { type: String, required: true },
    parentEmail: { type: String, required: true },
    parentPhone: { type: String, required: true },
    relationship: { type: String, required: true },
    childFullName: { type: String, required: true },
    childDob: { type: String, required: true },
    childAge: { type: Number, required: true },
    childGender: { type: String },
    schoolLevel: { type: String },
    technologyAccess: { type: String, enum: ['at-home', 'school'], required: true },
    hasDevice: { type: String, required: true },
    stableInternetConfirmed: { type: Boolean, required: true, default: false },
    learningInterests: { type: [String], default: [] },
    weekendAvailability: { type: [String], default: [] },
    expectations: { type: String, default: '' },
    guardianConsent: { type: Boolean, required: true },
    mediaConsent: { type: Boolean, default: false },
    privacyConsent: { type: Boolean, required: true },
    status: {
      type: String,
      enum: ['pending', 'reviewed', 'approved', 'rejected'],
      default: 'pending'
    },
    emailDelivery: {
      admin: {
        status: { type: String, default: 'pending' },
        sentAt: { type: Date, default: null },
        error: { type: String, default: null }
      },
      parent: {
        status: { type: String, default: 'pending' },
        sentAt: { type: Date, default: null },
        error: { type: String, default: null }
      }
    },
    duplicateKey: { type: String, index: true }
  },
  { timestamps: true }
);

const registrationCapacitySchema = new mongoose.Schema(
  {
    _id: { type: String, required: true },
    count: { type: Number, required: true, min: 0 }
  },
  { versionKey: false }
);

async function connectDatabase() {
  const mongoUri = process.env.MONGODB_URI;

  if (!mongoUri) {
    console.warn('MONGODB_URI is not set. Falling back to in-memory storage for local development only.');
    databaseReady = false;
    return;
  }

  try {
    await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 5000,
      retryWrites: true,
      w: 'majority'
    });
    Registration = mongoose.model('Registration', registrationSchema, 'registrations');
    RegistrationCapacity = mongoose.model('RegistrationCapacity', registrationCapacitySchema, 'registration_capacity');
    const existingCount = await Registration.countDocuments();
    await RegistrationCapacity.updateOne(
      { _id: 'registrations' },
      { $setOnInsert: { count: existingCount } },
      { upsert: true }
    );
    databaseReady = true;
    console.log('Connected to MongoDB Atlas database');
  } catch (error) {
    console.error('MongoDB connection failed:', error.message);
    databaseReady = false;
  }
}

async function findExistingRegistration(payload) {
  const duplicateKey = `${normalizeDuplicateKey(payload.parentEmail)}|${normalizeDuplicateKey(payload.childFullName)}|${normalizeDuplicateKey(payload.childDob)}`;

  if (databaseReady && Registration) {
    return Registration.findOne({ duplicateKey });
  }

  return memoryRegistrations.find((registration) => registration.duplicateKey === duplicateKey) || null;
}

async function createRegistrationRecord(payload) {
  const duplicateKey = `${normalizeDuplicateKey(payload.parentEmail)}|${normalizeDuplicateKey(payload.childFullName)}|${normalizeDuplicateKey(payload.childDob)}`;
  const registrationData = {
    ...payload,
    duplicateKey,
    emailDelivery: {
      admin: { status: 'pending', sentAt: null, error: null },
      parent: { status: 'pending', sentAt: null, error: null }
    }
  };

  if (databaseReady && Registration) {
    const capacity = await RegistrationCapacity.findOneAndUpdate(
      { _id: 'registrations', count: { $lt: MAX_REGISTRATIONS } },
      { $inc: { count: 1 } },
      { new: true }
    );

    if (!capacity) {
      const error = new Error('All 50 programme places have been filled.');
      error.code = 'REGISTRATION_CAPACITY_REACHED';
      throw error;
    }

    try {
      return await Registration.create(registrationData);
    } catch (error) {
      await RegistrationCapacity.updateOne(
        { _id: 'registrations', count: { $gt: 0 } },
        { $inc: { count: -1 } }
      );
      throw error;
    }
  }

  if (memoryRegistrations.length >= MAX_REGISTRATIONS) {
    const error = new Error('All 50 programme places have been filled.');
    error.code = 'REGISTRATION_CAPACITY_REACHED';
    throw error;
  }

  const newRecord = { _id: randomUUID(), ...registrationData, createdAt: new Date(), updatedAt: new Date() };
  memoryRegistrations.push(newRecord);
  return newRecord;
}

async function listRegistrations() {
  if (databaseReady && Registration) {
    return Registration.find({}).sort({ createdAt: -1 }).lean();
  }

  return [...memoryRegistrations].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

async function findRegistrationById(id) {
  if (databaseReady && Registration) {
    return Registration.findById(id);
  }

  return memoryRegistrations.find((item) => item._id === id) || null;
}

async function updateRegistrationById(id, update) {
  if (databaseReady && Registration) {
    return Registration.findByIdAndUpdate(id, update, { new: true });
  }

  const itemIndex = memoryRegistrations.findIndex((item) => item._id === id);
  if (itemIndex < 0) return null;
  memoryRegistrations[itemIndex] = { ...memoryRegistrations[itemIndex], ...update, updatedAt: new Date() };
  return memoryRegistrations[itemIndex];
}

async function buildEmailHtml(type, registration) {
  const lines = [
    '<h2>KEPHAS Young Builders</h2>',
    `<p><strong>Registration Reference:</strong> ${registration.reference}</p>`,
    `<p><strong>Parent / Guardian:</strong> ${registration.parentFullName}</p>`,
    `<p><strong>Parent Email:</strong> ${registration.parentEmail}</p>`,
    `<p><strong>Child:</strong> ${registration.childFullName}</p>`,
    `<p><strong>Date of birth:</strong> ${registration.childDob}</p>`,
    `<p><strong>Age:</strong> ${registration.childAge}</p>`,
    `<p><strong>Technology access:</strong> ${registration.technologyAccess}</p>`,
    `<p><strong>Laptop available:</strong> ${registration.hasDevice === 'yes' ? 'Yes' : 'No'}</p>`,
    `<p><strong>Stable internet confirmed:</strong> ${registration.stableInternetConfirmed ? 'Yes' : 'No'}</p>`,
    `<p><strong>Learning interests:</strong> ${registration.learningInterests.join(', ') || 'Not specified'}</p>`,
    `<p><strong>Class schedule:</strong> ${registration.weekendAvailability.join(', ') || 'Not specified'}</p>`,
    `<p><strong>Expectations:</strong> ${registration.expectations || 'Not provided'}</p>`,
    `<p><strong>Media consent:</strong> ${registration.mediaConsent ? 'Yes' : 'No'}</p>`,
    `<p><strong>Status:</strong> ${registration.status}</p>`
  ];

  if (type === 'parent') {
    lines.push(
      '<h3>Class schedule and payment</h3>',
      '<p>Classes are held live on Zoom on Saturdays from 9:00 AM to 3:00 PM.</p>',
      '<p>Each student needs a laptop and stable internet. There are only 50 places.</p>',
      '<p>A WhatsApp group will be created for programme information; joining details will be shared after registration.</p>',
      '<p><strong>Programme fee:</strong> ₦35,000</p>',
      '<p><strong>Bank:</strong> Moniepoint</p>',
      '<p><strong>Account number:</strong> 8131495622</p>',
      '<p><strong>Account name:</strong> Adekeye Cephas Precious</p>',
      `<p>Use your registration reference, ${registration.reference}, as the payment narration.</p>`,
      `<p>To share your registration reference on WhatsApp, open <a href="https://wa.me/2348131495622?text=${encodeURIComponent(`Hello, I have completed a KEPHAS Young Builders registration. My registration reference is ${registration.reference}.`)}">this prefilled message</a> and tap Send.</p>`,
      '<p>Questions? Message us on WhatsApp at 08131495622.</p>'
    );
  }

  return `<div>${lines.join('')}</div>`;
}

async function sendEmail({ to, subject, html, text }) {
  const resendApiKey = process.env.RESEND_API_KEY;
  const fromAddress = process.env.EMAIL_FROM || 'KEPHAS Young Builders <onboarding@resend.dev>';

  if (!resendApiKey) {
    return {
      delivered: false,
      status: 'skipped',
      error: 'RESEND_API_KEY is not configured.'
    };
  }

  try {
    const resend = new Resend(resendApiKey);
    const result = await resend.emails.send({
      from: fromAddress,
      to,
      subject,
      html,
      text
    });

    if (result.error) {
      return {
        delivered: false,
        status: 'failed',
        error: result.error.message || 'Email service rejected the request.'
      };
    }

    return {
      delivered: true,
      status: 'sent',
      id: result.data?.id || null,
      error: null
    };
  } catch (error) {
    return {
      delivered: false,
      status: 'failed',
      error: error.message || 'Unknown email delivery failure.'
    };
  }
}

async function dispatchEmailNotifications(registration) {
  const adminRecipients = [ADMIN_EMAIL];
  const adminHtml = await buildEmailHtml('admin', registration);
  const adminText = [
    `KEPHAS Young Builders Registration`,
    `Reference: ${registration.reference}`,
    `Parent/Guardian: ${registration.parentFullName}`,
    `Child: ${registration.childFullName}`,
    `Dob: ${registration.childDob}`,
    `Age: ${registration.childAge}`,
    `Laptop available: ${registration.hasDevice === 'yes' ? 'Yes' : 'No'}`,
    `Stable internet confirmed: ${registration.stableInternetConfirmed ? 'Yes' : 'No'}`,
    `Learning interests: ${registration.learningInterests.join(', ') || 'Not specified'}`,
    `Class schedule: ${registration.weekendAvailability.join(', ') || 'Not specified'}`,
    `Expectations: ${registration.expectations || 'Not provided'}`
  ].join('\n');

  const parentHtml = await buildEmailHtml('parent', registration);
  const parentText = [
    `Thank you for registering ${registration.childFullName} for KEPHAS Young Builders.`,
    `Your registration reference is ${registration.reference}.`,
    `Class schedule: Saturday, 9:00 AM to 3:00 PM.`,
    `Classes are held live on Zoom. Each student needs a laptop and stable internet.`,
    `There are only 50 places. A WhatsApp group will be created for programme information; joining details will be shared after registration.`,
    `Programme fee: ₦35,000.`,
    `Payment bank: Moniepoint.`,
    `Account number: 8131495622.`,
    `Account name: Adekeye Cephas Precious.`,
    `Use your registration reference (${registration.reference}) as the payment narration.`,
    `To share your registration reference on WhatsApp, open https://wa.me/2348131495622?text=${encodeURIComponent(`Hello, I have completed a KEPHAS Young Builders registration. My registration reference is ${registration.reference}.`)} and tap Send.`,
    `Questions? WhatsApp 08131495622.`,
    `We will review your application and contact you soon.`,
    `You can keep this reference for your records.`
  ].join('\n');

  const adminResult = await sendEmail({
    to: adminRecipients,
    subject: `New KEPHAS Young Builders registration - ${registration.reference}`,
    html: adminHtml,
    text: adminText
  });

  const parentResult = await sendEmail({
    to: [registration.parentEmail],
    subject: `Your KEPHAS Young Builders registration is received - ${registration.reference}`,
    html: parentHtml,
    text: parentText
  });

  const updatedEmailDelivery = {
    admin: {
      status: adminResult.status,
      sentAt: adminResult.delivered ? new Date() : null,
      error: adminResult.error
    },
    parent: {
      status: parentResult.status,
      sentAt: parentResult.delivered ? new Date() : null,
      error: parentResult.error
    }
  };

  await updateRegistrationById(registration._id, { emailDelivery: updatedEmailDelivery });

  return updatedEmailDelivery;
}

async function resendEmailForRegistration(registrationId) {
  const registration = await findRegistrationById(registrationId);
  if (!registration) {
    throw new Error('Registration not found.');
  }

  const updated = await dispatchEmailNotifications(registration);
  return { message: 'Email retry completed.', emailDelivery: updated };
}

function validateRegistrationRequest(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: 'Please correct the highlighted issues.',
      errors: errors.mapped()
    });
  }

  next();
}

const registrationValidators = [
  body('parentFullName').trim().isLength({ min: 2, max: 120 }).withMessage('Parent full name must be between 2 and 120 characters.'),
  body('parentEmail').trim().isEmail().normalizeEmail().withMessage('A valid parent email is required.'),
  body('parentPhone').trim().isLength({ min: 7, max: 20 }).withMessage('Phone number must be between 7 and 20 characters.'),
  body('relationship').trim().isLength({ min: 2, max: 30 }).withMessage('Relationship is invalid.'),
  body('childFullName').trim().isLength({ min: 2, max: 120 }).withMessage('Child full name must be between 2 and 120 characters.'),
  body('childDob').trim().isISO8601().withMessage('Please provide a valid date of birth.'),
  body('childGender').optional({ values: 'falsy' }).trim().isLength({ min: 2, max: 30 }),
  body('schoolLevel').optional({ values: 'falsy' }).trim().isLength({ min: 2, max: 40 }),
  body('technologyAccess').trim().isIn(['at-home', 'school']).withMessage('Please select where your child will access the classes.'),
  body('hasDevice').equals('yes').withMessage('Each student needs access to a laptop for class.'),
  body('stableInternetConfirmed')
    .isBoolean({ strict: true })
    .custom((confirmed) => confirmed === true)
    .withMessage('Stable internet is required for Zoom classes.'),
  body('learningInterests').optional().isArray({ min: 1 }).withMessage('Please choose at least one learning interest.'),
  body('weekendAvailability')
    .isArray({ min: 1, max: 1 })
    .withMessage('Classes are held on Saturdays only.')
    .bail()
    .custom((days) => days[0] === 'Saturday')
    .withMessage('Classes are held on Saturdays only.'),
  body('expectations').optional().trim().isLength({ max: 1500 }).withMessage('Expectations must be 1500 characters or less.'),
  body('guardianConsent').isBoolean().withMessage('Guardian consent is required.'),
  body('privacyConsent').isBoolean().withMessage('Privacy consent is required.'),
  body('mediaConsent').optional().isBoolean()
];

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    database: databaseReady ? 'connected' : 'local-memory-fallback',
    timestamp: new Date().toISOString()
  });
});

app.post('/api/registrations', registrationValidators, validateRegistrationRequest, async (req, res) => {
  const body = sanitizePayload(req.body);

  const age = parseAgeFromDob(body.childDob);
  if (age === null || age < 10 || age > 19) {
    return res.status(400).json({
      message: 'Child must be between 10 and 19 years old to register.',
      errors: { childDob: 'Age must be between 10 and 19.' }
    });
  }

  const payload = {
    parentFullName: body.parentFullName,
    parentEmail: String(body.parentEmail).toLowerCase(),
    parentPhone: body.parentPhone,
    relationship: body.relationship,
    childFullName: body.childFullName,
    childDob: body.childDob,
    childAge: age,
    childGender: body.childGender || '',
    schoolLevel: body.schoolLevel || '',
    technologyAccess: body.technologyAccess,
    hasDevice: body.hasDevice,
    stableInternetConfirmed: body.stableInternetConfirmed === true,
    learningInterests: Array.isArray(body.learningInterests) ? body.learningInterests.map((item) => sanitizeText(item)) : [],
    weekendAvailability: ['Saturday'],
    expectations: body.expectations || '',
    guardianConsent: body.guardianConsent === true,
    mediaConsent: body.mediaConsent === true,
    privacyConsent: body.privacyConsent === true,
    status: 'pending',
    reference: generateReference()
  };

  if (!payload.guardianConsent || !payload.privacyConsent) {
    return res.status(400).json({
      message: 'Guardian consent and privacy consent are required.',
      errors: {
        guardianConsent: 'Guardian consent is required.',
        privacyConsent: 'Privacy consent is required.'
      }
    });
  }

  const existing = await findExistingRegistration(payload);
  if (existing) {
    return res.status(409).json({
      message: 'This child appears to already be registered with the same parent email and date of birth.',
      reference: existing.reference,
      duplicate: true
    });
  }

  try {
    const savedRegistration = await createRegistrationRecord(payload);

    setImmediate(async () => {
      try {
        await dispatchEmailNotifications(savedRegistration);
      } catch (emailError) {
        console.error('Email dispatch failed:', emailError.message);
      }
    });

    return res.status(201).json({
      message: 'Registration submitted successfully.',
      registration: {
        _id: savedRegistration._id,
        reference: savedRegistration.reference,
        status: savedRegistration.status,
        emailDelivery: savedRegistration.emailDelivery
      }
    });
  } catch (error) {
    if (error.code === 'REGISTRATION_CAPACITY_REACHED') {
      return res.status(409).json({ message: error.message });
    }
    console.error('Registration creation failed:', error);
    return res.status(500).json({
      message: 'The registration could not be saved. Please try again.',
      error: error.message
    });
  }
});

app.post('/api/admin/login', async (req, res) => {
  const username = sanitizeText(req.body.username || '');
  const password = sanitizeText(req.body.password || '');

  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ message: 'Invalid admin credentials.' });
  }

  const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
  return res.json({ token, message: 'Admin login successful.' });
});

function adminAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: 'Authentication required.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin' || decoded.username !== ADMIN_USERNAME) {
      return res.status(403).json({ message: 'Administrator access required.' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

app.get('/api/admin/registrations', adminAuth, async (_req, res) => {
  try {
    const registrations = await listRegistrations();
    res.json({ registrations });
  } catch (error) {
    res.status(500).json({ message: 'Unable to load registrations.', error: error.message });
  }
});

app.patch('/api/admin/registrations/:id/status', adminAuth, async (req, res) => {
  const status = sanitizeText(req.body.status || '');
  const validStatuses = ['pending', 'reviewed', 'approved', 'rejected'];

  if (!validStatuses.includes(status)) {
    return res.status(400).json({ message: 'Invalid registration status.' });
  }

  try {
    const updated = await updateRegistrationById(req.params.id, { status });
    if (!updated) {
      return res.status(404).json({ message: 'Registration not found.' });
    }

    res.json({ message: 'Registration status updated.', registration: updated });
  } catch (error) {
    res.status(500).json({ message: 'Status update failed.', error: error.message });
  }
});

app.patch('/api/admin/registrations/:id/resend-email', adminAuth, async (req, res) => {
  try {
    const result = await resendEmailForRegistration(req.params.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: error.message || 'Unable to resend email.' });
  }
});

app.get('/api/admin/registrations/export', adminAuth, async (_req, res) => {
  try {
    const registrations = await listRegistrations();
    const csvRows = [['reference', 'parentFullName', 'parentEmail', 'parentPhone', 'relationship', 'childFullName', 'childDob', 'childAge', 'status', 'mediaConsent', 'emailDeliveryAdminStatus', 'emailDeliveryParentStatus']];

    registrations.forEach((registration) => {
      csvRows.push([
        registration.reference,
        registration.parentFullName,
        registration.parentEmail,
        registration.parentPhone,
        registration.relationship,
        registration.childFullName,
        registration.childDob,
        registration.childAge,
        registration.status,
        registration.mediaConsent ? 'true' : 'false',
        registration.emailDelivery?.admin?.status || 'unknown',
        registration.emailDelivery?.parent?.status || 'unknown'
      ]);
    });

    const csv = csvRows.map((row) => row.map((value) => `"${String(value ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="kephas-registrations.csv"');
    res.send(csv);
  } catch (error) {
    res.status(500).json({ message: 'Unable to export registrations.', error: error.message });
  }
});

if (existsSync(path.join(clientBuildDirectory, 'index.html'))) {
  app.use(express.static(clientBuildDirectory));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) return next();
    res.sendFile(path.join(clientBuildDirectory, 'index.html'), (error) => {
      if (error) next(error);
    });
  });
}

app.use((err, _req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Unexpected server error.' });
});

connectDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`KEPHAS registration portal running on http://localhost:${PORT}`);
  });
});
