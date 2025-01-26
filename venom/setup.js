const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const fs = require('fs');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async function setupAdmin() {
    console.log('\n=== Mars Network Admin Setup ===\n');

    // Admin kullanıcı adı ve şifre oluşturma
    const username = await question('Enter admin username: ');
    const password = await question('Enter admin password: ');
    
    // Şifreyi hash'le
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // 2FA secret oluştur
    const twoFactorSecret = speakeasy.generateSecret({
        name: "Mars Network Admin"
    });

    // QR kod oluştur
    const qrCodeUrl = await qrcode.toDataURL(twoFactorSecret.otpauth_url);

    // Güvenli bir JWT secret oluştur
    const jwtSecret = require('crypto').randomBytes(64).toString('hex');

    // .env dosyasını oluştur
    const envContent = `
ADMIN_USERNAME=${username}
ADMIN_PASSWORD_HASH=${passwordHash}
JWT_SECRET=${jwtSecret}
TWO_FACTOR_SECRET=${twoFactorSecret.base32}
FRONTEND_URL=http://localhost:3000
PORT=5000
    `.trim();

    fs.writeFileSync('.env', envContent);

    // QR kodu kaydet
    fs.writeFileSync('2fa-qr.html', `
        <html>
            <body style="display: flex; justify-content: center; align-items: center; height: 100vh; flex-direction: column;">
                <h2>Scan this QR code with your 2FA app</h2>
                <img src="${qrCodeUrl}">
                <p>Manual entry code: ${twoFactorSecret.base32}</p>
            </body>
        </html>
    `);

    console.log('\n=== Setup Complete ===');
    console.log('1. Environment variables saved to .env');
    console.log('2. Open 2fa-qr.html in your browser to scan the QR code');
    console.log('3. Use Google Authenticator or similar app to scan the code');
    console.log('\nTest your 2FA code:');
    
    // 2FA test
    const testCode = await question('Enter the code from your 2FA app: ');
    const verified = speakeasy.totp.verify({
        secret: twoFactorSecret.base32,
        encoding: 'base32',
        token: testCode
    });

    if (verified) {
        console.log('\n✅ 2FA verification successful!');
        console.log('\nYour admin credentials:');
        console.log(`Username: ${username}`);
        console.log('Password: [HIDDEN]');
        console.log('\nMake sure to:');
        console.log('1. Save these credentials securely');
        console.log('2. Delete 2fa-qr.html after setup');
        console.log('3. Keep your .env file secure');
    } else {
        console.log('\n❌ 2FA verification failed!');
        console.log('Please try the setup again.');
    }

    rl.close();
}

function question(query) {
    return new Promise(resolve => rl.question(query, resolve));
}

setupAdmin().catch(console.error); 