const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Resolve path to .env and .env.example
const envPath = path.join(__dirname, '..', '.env');
const examplePath = path.join(__dirname, '..', '.env.example');

if (!fs.existsSync(examplePath)) {
  console.error('Error: .env.example does not exist.');
  process.exit(1);
}

// Generate a cryptographically secure random 64-character hex secret (32 bytes)
const secret = crypto.randomBytes(32).toString('hex');

if (fs.existsSync(envPath)) {
  console.log('.env file already exists. Checking CSRF_SECRET...');
  const currentContent = fs.readFileSync(envPath, 'utf8');
  if (/^CSRF_SECRET=.+$/m.test(currentContent)) {
    console.log('CSRF_SECRET is already set in .env.');
    process.exit(0);
  } else {
    const updated = currentContent.replace(/^CSRF_SECRET=.*$/m, `CSRF_SECRET=${secret}`);
    fs.writeFileSync(envPath, updated, 'utf8');
    console.log('Updated CSRF_SECRET in existing .env.');
    process.exit(0);
  }
}

// Read template and substitute secret
const template = fs.readFileSync(examplePath, 'utf8');
const envContent = template.replace(/^CSRF_SECRET=.*$/m, `CSRF_SECRET=${secret}`);

fs.writeFileSync(envPath, envContent, 'utf8');
console.log('Successfully created .env file with a generated random CSRF_SECRET.');
