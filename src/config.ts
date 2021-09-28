export const PORT = parseInt(process.env.PORT || "3000");
export const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
export const METHODS_WITHOUT_BODY = ["OPTIONS", "HEAD", "GET"]
