const nodemailer = require('nodemailer');
const logger = require('../config/logger');
const path = require('path');
const ejs = require('ejs');
const fs = require('fs');
const emailTemplates = require('../utils/emailTemplates');

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

  /**
   * Send an email with HTML content
   * @param {Object} options - Email options
   * @param {string} options.to - Recipient email address
   * @param {string} options.subject - Email subject
   * @param {string} options.html - HTML content of the email
   * @returns {Promise<Object>} Email sending result
   */
  async sendEmail({ to, subject, html }) {
    if (!this.isEnabled || !this.transporter) {
      logger.warn(`Email service is disabled. Would send email to ${to} with subject: ${subject}`);
      return { message: 'Email service is disabled' };
    }

    try {
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
      logger.warn('Email service is not enabled. Skipping welcome email.');
      return;
    }

    try {
      const templatePath = path.join(__dirname, '../templates/welcome-email.html');
      const template = fs.readFileSync(templatePath, 'utf-8');
      
      const html = ejs.render(template, {
        name: user.firstName,
        email: user.email,
        currentYear: new Date().getFullYear(),
        appName: 'Fintex',
        supportEmail: 'support@fintex.com'
      });

      await this.sendEmail({
        to: user.email,
        subject: 'Welcome to Fintex!',
        html,
      });
    } catch (error) {
      logger.error('Failed to send welcome email:', error);
      throw error;
    }
  }

  /**
   * Send password change confirmation email
   * @param {string} email - User's email
   * @param {string} name - User's name
   * @returns {Promise<void>}
   */
  async sendPasswordChangeConfirmation(email, name) {
    if (!this.isEnabled) {
      logger.warn('Email service is not enabled. Skipping password change confirmation email.');
      return;
    }

    try {
      const html = await emailTemplates.getPasswordChangeConfirmationEmail(name);
      
      await this.sendEmail({
        to: email,
        subject: 'Your Password Has Been Changed',
        html,
      });
      
      logger.info(`Password change confirmation sent to ${email}`);
    } catch (error) {
      logger.error('Failed to send password change confirmation email:', error);
      throw error;
    }
  }

  /**
   * Send password reset email
   * @param {string} email - User's email
   * @param {string} name - User's name
   * @param {string} token - Password reset token
   * @param {string} resetUrl - Full reset URL with token
   * @returns {Promise<void>}
   */
  async sendPasswordResetEmail(email, name, token, resetUrl) {
    if (!this.isEnabled) {
      logger.warn('Email service is not enabled. Skipping password reset email.');
      return;
    }

    try {
      const html = await emailTemplates.getPasswordResetEmail(name, resetUrl);
      
      await this.sendEmail({
        to: email,
        subject: 'Reset Your Password',
        html,
      });
      
      logger.info(`Password reset email sent to ${email}`);
    } catch (error) {
      logger.error('Failed to send password reset email:', error);
      throw error;
    }
  }

  /**
   * Send password reset confirmation email
   * @param {string} email - User's email
   * @param {string} name - User's name
   * @returns {Promise<void>}
   */
  async sendPasswordResetConfirmation(email, name) {
    if (!this.isEnabled) {
      logger.warn('Email service is not enabled. Skipping password reset confirmation email.');
      return;
    }

    try {
      const html = await emailTemplates.getPasswordResetConfirmationEmail(name);
      
      await this.sendEmail({
        to: email,
        subject: 'Your Password Has Been Reset',
        html,
      });
      
      logger.info(`Password reset confirmation sent to ${email}`);
    } catch (error) {
      logger.error('Failed to send password reset confirmation email:', error);
      throw error;
    }
  }

  /**
   * Send password change confirmation email
   * @param {string} email - User's email
   * @param {string} name - User's name
   * @returns {Promise<void>}
   */
  async sendPasswordChangeConfirmation(email, name) {
    if (!this.isEnabled) {
      logger.warn('Email service is not enabled. Skipping password change confirmation email.');
      return;
    }

    try {
      const html = await emailTemplates.getPasswordChangeConfirmationEmail(name);
      
      await this.sendEmail({
        to: email,
        subject: 'Your Password Has Been Changed',
        html,
      });
      
      logger.info(`Password change confirmation sent to ${email}`);
    } catch (error) {
      logger.error('Failed to send password change confirmation email:', error);
      throw error;
    }
  }
}

module.exports = new EmailService();
