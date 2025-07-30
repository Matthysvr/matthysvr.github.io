'use strict';

// Assessment password protection and content management
class AssessmentManager {
  constructor() {
    this.encryptedContent = null;
    this.init();
  }

  async init() {
    this.setupEventListeners();
    document.body.classList.add('password-screen-active');
    await this.loadEncryptedContent();
    await this.checkUrlPassword();
  }

  setupEventListeners() {
    const passwordForm = document.getElementById('password-form');
    const passwordInput = document.getElementById('password-input');

    if (passwordForm) {
      passwordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await this.validatePassword(passwordInput.value);
      });
    }

    // Allow Enter key to submit
    if (passwordInput) {
      passwordInput.addEventListener('keypress', async (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          await this.validatePassword(passwordInput.value);
        }
      });
    }
  }

  async checkUrlPassword() {
    const urlParams = new URLSearchParams(window.location.search);
    const urlPassword = urlParams.get('password');
    
    if (urlPassword) {
      await this.validatePassword(urlPassword);
    }
  }

  async validatePassword(inputPassword) {
    const passwordScreen = document.getElementById('password-screen');
    const assessmentContent = document.getElementById('assessment-content');
    const passwordError = document.getElementById('password-error');
    const passwordInput = document.getElementById('password-input');

    try {
      // Try to decrypt the content with the provided password
      const decryptedContent = await this.decrypt(this.encryptedContent, inputPassword);
      
      if (decryptedContent) {
        // Decryption successful - hide password screen and show content
        passwordScreen.style.display = 'none';
        assessmentContent.style.display = 'block';
        document.body.classList.remove('password-screen-active');
        
        // Clear any error messages
        if (passwordError) {
          passwordError.style.display = 'none';
        }
        
        // Clear password input
        if (passwordInput) {
          passwordInput.value = '';
        }
        
        // Display the decrypted content
        const assessmentText = document.getElementById('assessment-text');
        if (assessmentText) {
          assessmentText.innerHTML = decryptedContent;
        }
        
        // Update URL without password parameter
        const url = new URL(window.location);
        url.searchParams.delete('password');
        window.history.replaceState({}, '', url);
        
      } else {
        // Decryption failed - show error message
        if (passwordError) {
          passwordError.style.display = 'block';
        }
        
        // Clear password input
        if (passwordInput) {
          passwordInput.value = '';
          passwordInput.focus();
        }
      }
    } catch (error) {
      // Decryption error - show error message
      console.error('Password validation error:', error);
      if (passwordError) {
        passwordError.style.display = 'block';
      }
      
      // Clear password input
      if (passwordInput) {
        passwordInput.value = '';
        passwordInput.focus();
      }
    }
  }

  async loadEncryptedContent() {
    try {
      // Load the encrypted content file
      const response = await fetch('./assessment-content.encrypted');
      if (response.ok) {
        this.encryptedContent = await response.text();
      } else {
        console.error('Failed to load encrypted content file');
        this.showError('Content file not found');
      }
    } catch (error) {
      console.error('Error loading encrypted content:', error);
      this.showError('Failed to load content');
    }
  }

  showError(message) {
    const assessmentText = document.getElementById('assessment-text');
    if (assessmentText) {
      assessmentText.innerHTML = `<div style="color: #ff6b6b; text-align: center; padding: 20px;">
        <h3>Error</h3>
        <p>${message}</p>
      </div>`;
    }
  }

  // Decryption function using Web Crypto API
  async decrypt(encryptedText, password) {
    try {
      // Parse the encrypted text (format: salt:iv:encrypted)
      const textParts = encryptedText.split(':');
      if (textParts.length < 3) {
        console.error('Invalid encrypted format. Expected salt:iv:encrypted');
        return null;
      }
      
      const saltHex = textParts.shift();
      const ivHex = textParts.shift();
      const encrypted = textParts.join(':');
      
      // Convert hex strings to ArrayBuffers
      const salt = this.hexToArrayBuffer(saltHex);
      const iv = this.hexToArrayBuffer(ivHex);
      const encryptedData = this.hexToArrayBuffer(encrypted);
      
      // Derive key from password using PBKDF2
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );
      
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-CBC', length: 256 },
        false,
        ['decrypt']
      );
      
      // Decrypt the data
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: iv },
        key,
        encryptedData
      );
      
      return new TextDecoder().decode(decrypted);
    } catch (error) {
      console.error('Decryption failed:', error);
      return null;
    }
  }

  // Helper function to convert hex string to ArrayBuffer
  hexToArrayBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes.buffer;
  }
}

// Initialize the assessment manager when the page loads
document.addEventListener('DOMContentLoaded', () => {
  new AssessmentManager();
}); 