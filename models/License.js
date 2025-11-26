const mongoose = require("mongoose");

const licenseSchema = new mongoose.Schema({
  licenseKey: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
  },
  status: {
    type: String,
    enum: ["active", "suspended", "expired"],
    default: "active",
  },
  tier: {
    type: String,
    default: null,
  },
  appSheetsUrl: {
    type: String,
    default: null,
  },
  expiryDate: {
    type: Date,
    required: true,
  },
  maxDevices: {
    type: Number,
    default: null,
  },
  devices: [
    {
      fingerprint: String,
      activatedAt: { type: Date, default: Date.now },
      lastUsed: Date,
      userAgent: String,
    },
  ],
  googleSheetsUrl: String,
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

// Auto-update updatedAt
licenseSchema.pre("save", function (next) {
  this.updatedAt = Date.now();
  next();
});

// Index for faster queries
licenseSchema.index({ email: 1 });
licenseSchema.index({ status: 1 });

module.exports = mongoose.model("License", licenseSchema);
