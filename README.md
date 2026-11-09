# KEPHAS Builders API

Express API for KEPHAS Young Builders registration, administrator access, MongoDB persistence, and Resend email notifications.

## Run locally

1. Install dependencies with `npm install`.
2. Set the environment variables listed below in your host or local environment.
3. Run `npm start`.

The API listens on `PORT` (default `5000`). Health check: `/api/health`.

## Environment variables

- `PORT`
- `CLIENT_URL` (allowed frontend origin for CORS)
- `MONGODB_URI`
- `JWT_SECRET`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `ADMIN_EMAIL`
- `RESEND_API_KEY`
- `EMAIL_FROM`
- `RATE_LIMIT_WINDOW_MS` (optional)
- `RATE_LIMIT_MAX` (optional)

Do not commit `.env` files or credentials. Configure these values in the hosting provider's environment settings. Use a production MongoDB database and a verified Resend sender domain.

If MongoDB is unavailable, the service reports `local-memory-fallback` at `/api/health`; registrations in fallback mode are not durable and must not be used for production traffic.
