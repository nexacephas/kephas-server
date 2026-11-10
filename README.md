# KEPHAS Builders API

Express API for KEPHAS Young Builders registration, administrator access, MongoDB persistence, and Resend email notifications.

Classes are held live on Zoom on Saturdays from 9:00 AM to 3:00 PM. Capacity is limited to 50 registrations. Each student needs a laptop and stable internet. WhatsApp group details are shared after registration; questions can be sent to 08131495622.

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
