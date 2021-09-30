const dotenv = require('dotenv');
dotenv.config({path: `.env.${process.env.NODE_ENV || "sandbox"}`});

export const PORT = parseInt(process.env.PORT || "3000");
export const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
export const METHODS_WITHOUT_BODY = ["OPTIONS", "HEAD", "GET"]
export const MAX_FAILURES_TO_CLAIM_QR = 5;
export const DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS = 300;
