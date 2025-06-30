# Fintex Backend

A professional Node.js backend with MongoDB, Express, and email notifications.

## Features

- **RESTful API** with Express.js
- **MongoDB** database with Mongoose
- **JWT Authentication**
- **Logging** with Winston
- **Email Notifications** with Nodemailer
- **Error Handling** with custom error classes
- **Environment Configuration**
- **Request Validation**
- **API Documentation** with Swagger

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (local or Atlas)
- npm or yarn

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file in the root directory and configure the environment variables (use `.env.example` as a reference)
4. Start the development server:
   ```bash
   npm run dev
   ```

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```
# Server Configuration
PORT=3000
NODE_ENV=development

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/fintex

# JWT Configuration
JWT_SECRET=your_jwt_secret_key_here
JWT_EXPIRES_IN=30d
JWT_COOKIE_EXPIRES_IN=30

# Email Configuration
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USERNAME=your_email@example.com
EMAIL_PASSWORD=your_email_password
EMAIL_FROM=Fintex <noreply@fintex.com>

# Frontend URL (for email links)
FRONTEND_URL=http://localhost:3000

# Logging
LOG_LEVEL=info
```

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user
- `POST /api/auth/refresh-token` - Refresh authentication token

### Health Check

- `GET /api/health` - Health check endpoint

## Project Structure

```
backend/
├── src/
│   ├── config/         # Configuration files
│   ├── controllers/    # Route controllers
│   ├── middlewares/    # Custom express middlewares
│   ├── models/         # Mongoose models
│   ├── routes/         # API routes
│   ├── services/       # Business logic and external services
│   ├── templates/      # Email templates
│   ├── utils/          # Utility classes and functions
│   ├── app.js          # Express app setup
│   └── server.js       # Server startup
├── .env                # Environment variables
├── .gitignore
└── package.json
```

## Development

- Start development server: `npm run dev`
- Lint code: `npm run lint`
- Format code: `npm run format`

## Production

- Build application: `npm run build`
- Start production server: `npm start`

## License

MIT
