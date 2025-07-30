// Utility script to encrypt assessment content
// Run this with Node.js: node encrypt-content.js

const fs = require('fs');
const crypto = require('crypto');

class ContentEncryptor {
  constructor(password = 'password') {
    this.password = password;
    this.algorithm = 'aes-256-cbc';
  }

  encrypt(text) {
    const iv = crypto.randomBytes(16);
    const salt = crypto.randomBytes(16);
    
    // Use PBKDF2 for key derivation (compatible with Web Crypto API)
    const key = crypto.pbkdf2Sync(this.password, salt, 100000, 32, 'sha256');
    
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Store format: salt:iv:encrypted
    return salt.toString('hex') + ':' + iv.toString('hex') + ':' + encrypted;
  }

  decrypt(encryptedText) {
    const textParts = encryptedText.split(':');
    const saltHex = textParts.shift();
    const ivHex = textParts.shift();
    const encrypted = textParts.join(':');
    
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    
    // Use PBKDF2 for key derivation
    const key = crypto.pbkdf2Sync(this.password, salt, 100000, 32, 'sha256');
    
    const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  encryptFile(inputFile, outputFile) {
    try {
      const content = fs.readFileSync(inputFile, 'utf8');
      const encrypted = this.encrypt(content);
      fs.writeFileSync(outputFile, encrypted);
      console.log(`Content encrypted and saved to ${outputFile}`);
    } catch (error) {
      console.error('Error encrypting file:', error);
    }
  }

  decryptFile(inputFile, outputFile) {
    try {
      const encrypted = fs.readFileSync(inputFile, 'utf8');
      const decrypted = this.decrypt(encrypted);
      fs.writeFileSync(outputFile, decrypted);
      console.log(`Content decrypted and saved to ${outputFile}`);
    } catch (error) {
      console.error('Error decrypting file:', error);
    }
  }
}

// Example usage
if (require.main === module) {
  const encryptor = new ContentEncryptor();
  
  // Check if assessment-content.txt exists
  if (fs.existsSync('./assessment-content.txt')) {
    console.log('Encrypting assessment content...');
    encryptor.encryptFile('./assessment-content.txt', './assessment-content.encrypted');
    console.log('Original file can be deleted or kept for editing');
  } else {
    console.log('assessment-content.txt not found. Creating sample encrypted content...');
    const sampleContent = `<h2>Sample Assessment Content</h2>
<p>This is a sample of encrypted content. Replace with your actual assessment.</p>`;
    fs.writeFileSync('./assessment-content.txt', sampleContent);
    encryptor.encryptFile('./assessment-content.txt', './assessment-content.encrypted');
  }
}

module.exports = ContentEncryptor; 