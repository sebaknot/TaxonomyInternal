import crypto from 'node:crypto';
console.log('# Add these to your .env file');
console.log(`APP_ENCRYPTION_KEY=${crypto.randomBytes(32).toString('base64')}`);
console.log(`SESSION_SECRET=${crypto.randomBytes(48).toString('base64')}`);
