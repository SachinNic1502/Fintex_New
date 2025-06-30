const fs = require('fs');
const path = require('path');
const ejs = require('ejs');

const templatesDir = path.join(__dirname, '../templates');

/**
 * Render an email template with the given data
 * @param {string} templateName - Name of the template file (without extension)
 * @param {Object} data - Data to render the template with
 * @returns {Promise<string>} Rendered HTML
 */
const renderTemplate = async (templateName, data = {}) => {
  try {
    const templatePath = path.join(templatesDir, `${templateName}.html`);
    const template = fs.readFileSync(templatePath, 'utf-8');
    
    // Add current year to all templates
    const templateData = {
      ...data,
      currentYear: new Date().getFullYear()
    };
    
    return ejs.render(template, templateData);
  } catch (error) {
    console.error(`Error rendering template ${templateName}:`, error);
    throw new Error('Failed to render email template');
  }
};

/**
 * Get the password reset email content
 * @param {string} name - User's name
 * @param {string} resetLink - Password reset link
 * @returns {Promise<string>} Rendered HTML email
 */
const getPasswordResetEmail = async (name, resetLink) => {
  return renderTemplate('forgot-password', {
    name,
    resetLink,
    supportEmail: 'support@fintex.com',
    appName: 'Fintex'
  });
};

/**
 * Get the password reset confirmation email content
 * @param {string} name - User's name
 * @returns {Promise<string>} Rendered HTML email
 */
const getPasswordResetConfirmationEmail = async (name) => {
  return renderTemplate('password-reset-confirmation', {
    name,
    supportEmail: 'support@fintex.com',
    appName: 'Fintex'
  });
};

/**
 * Get the password change confirmation email content
 * @param {string} name - User's name
 * @returns {Promise<string>} Rendered HTML email
 */
const getPasswordChangeConfirmationEmail = async (name) => {
  return renderTemplate('password-change-confirmation', {
    name,
    supportEmail: 'support@fintex.com',
    appName: 'Fintex'
  });
};

module.exports = {
  renderTemplate,
  getPasswordResetEmail,
  getPasswordResetConfirmationEmail,
  getPasswordChangeConfirmationEmail
};
