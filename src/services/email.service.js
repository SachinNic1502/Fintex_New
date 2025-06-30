const nodemailer = require('nodemailer');
const logger = require('../config/logger');
const path = require('path');
const ejs = require('ejs');
const fs = require('fs');

class EmailService {
  constructor() {
    // Check if email configuration is provided
    if (!process.env.EMAIL_HOST || !process.env.EMAIL_PORT || 
        !process.env.EMAIL_USERNAME || !process.env.EMAIL_PASSWORD) {
      logger.warn('Email configuration is incomplete. Email service will run in test mode.');
      this.transporter = null;
      this.isEnabled = false;
      return;
    }

    try {
      this.transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT, 10),
        secure: process.env.EMAIL_PORT === '465', // true for 465, false for other ports
        auth: {
          user: process.env.EMAIL_USERNAME,
          pass: process.env.EMAIL_PASSWORD,
        },
        tls: {
          rejectUnauthorized: process.env.NODE_ENV === 'production', // Only reject in production
        },
      });

      this.isEnabled = true;
      // Verify connection configuration in the background
      this.verifyConnection().catch(error => {
        logger.error('Email service verification failed:', error);
        this.isEnabled = false;
      });
    } catch (error) {
      logger.error('Failed to initialize email service:', error);
      this.transporter = null;
      this.isEnabled = false;
    }
  }

  async verifyConnection() {
    if (!this.transporter) {
      throw new Error('Email transporter not initialized');
    }
    
    try {
      await this.transporter.verify();
      logger.info('Email server is ready to send messages');
      return true;
    } catch (error) {
      logger.error('Email server connection error:', error);
      this.isEnabled = false;
      throw new Error('Failed to connect to email server');
    }
  }

  async sendEmail(to, subject, template, data = {}) {
    if (!this.isEnabled || !this.transporter) {
      logger.warn(`Email service is disabled. Would send email to ${to} with subject: ${subject}`);
      return { message: 'Email service is disabled' };
    }

    try {
      // Get the email template
      const templatePath = path.join(
        __dirname,
        '..',
        'templates',
        'emails',
        `${template}.ejs`
      );

      // Check if template exists
      if (!fs.existsSync(templatePath)) {
        logger.error(`Email template ${template} not found at ${templatePath}`);
        throw new Error(`Email template ${template} not found`);
      }

      // Render the email template with EJS
      const templateContent = fs.readFileSync(templatePath, 'utf-8');
      const html = ejs.render(templateContent, data);

      // Send mail with defined transport object
      const mailOptions = {
        from: process.env.EMAIL_FROM || 'Fintex <noreply@fintex.com>',
        to,
        subject,
        html,
      };

      const info = await this.transporter.sendMail(mailOptions);
      logger.info(`Email sent to ${to}: ${info.messageId}`);
      return info;
    } catch (error) {
      logger.error('Error sending email:', error);
      // Don't throw error to prevent breaking the application flow
      return { error: 'Failed to send email', details: error.message };
    }
  }

  // Common email methods
  async sendWelcomeEmail(user) {
    if (!this.isEnabled) {
      logger.info(`[Email Service] Welcome email would be sent to: ${user.email}`);
      return { message: 'Welcome email would be sent in production' };
    }
    
    return this.sendEmail(
      user.email,
      'Welcome to Fintex',
      'welcome',
      { name: user.name }
    );
  }

  async sendPasswordResetEmail(user, resetToken) {
    if (!this.isEnabled) {
      logger.info(`[Email Service] Password reset email would be sent to: ${user.email}`);
      return { message: 'Password reset email would be sent in production' };
    }
    
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
    return this.sendEmail(
      user.email,
      'Password Reset Request',
      'password-reset',
      { name: user.name, resetUrl }
    );
  }
}

module.exports = new EmailService();
