import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import db from './config/db.js';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import ms from 'ms';
const app = express();

dotenv.config();
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Token Generation
function generateTokens(userPayload) {
    const accessToken = jwt.sign(userPayload, process.env.JWT_ACCESS_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign(userPayload,process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });
    return { accessToken, refreshToken };
}

// authorize user 
function authenticateToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if(token == null) return res.status(401).send({message: "No token provided!"});
    jwt.verify(token, process.env.JWT_ACCESS_SECRET, (err,user)=>{
        if(err){
            if(err.name === 'TokenExpiredError') {
                return res.status(403).json({ message: 'Access token expired.',expired:true });
            }
            console.error('JWT verification error:', err);
            return res.status(403).json({ message: 'Invalid access token.' });
        }
        req.user = user;
        next();
    });
}


// Test Route (protected)
app.get('/resource', authenticateToken, async (req, res) => {
    // ({ id: 1, username: 'ajay123' })
    console.log('Authenticated user:', req.user.id);
    let result = await db.query("SELECT * FROM users WHERE user_id = $1;", [req.user.id]);
    res.json({
        message: "Welcome to the protected homepage!",
        user: result.rows[0] ? { id: result.rows[0].user_id, username: result.rows[0].username, email: result.rows[0].email } : null,
        token_payload: req.user
    });
});


// User Registration
app.post('/register', async (req,res)=>{
    const user = req.body;
    try{
        await db.query("INSERT INTO users (username,email, password_hash) VALUES ($1, $2, $3);", [user.username, user.email, bcrypt.hashSync(user.password, 10)]);
        res.status(201).send({message: "User registered successfully!"});
    }catch(err){
        if(err.code === '23505') {
            const match = err.detail.match(/Key \((.+?)\)=\((.+?)\) already exists/);
            if(match && match.length > 2) {
                const key = match[1];
                const value = match[2];
                console.log({message : `The user with ${key}, Value: ${value} already exists!`});
                if (key === 'username') {
                    return res.status(409).send({message: `Username ${value} already exists`});
                }else if (key === 'email') {
                    return res.status(409).send({message: `Email ${value} already exists`});
                }
            }
        }
        console.error('Registration error:', err);
        return res.status(500).json({ message: "Internal server error during registration." });
    }
});

// User Login
app.post('/login', async (req,res)=>{
    const user = req.body;
    try{
        const result = await db.query("SELECT * FROM users WHERE (username = $1 OR email = $1);", [user.login_id]);
        if(result.rowCount){
            if(result.rows[0].password_hash && bcrypt.compareSync(user.password, result.rows[0].password_hash)){
                const userPayload = {
                    id: result.rows[0].user_id,
                    username: result.rows[0].username,
                    email: result.rows[0].email
                };
                const {accessToken, refreshToken} = generateTokens(userPayload);
                const refreshTokenHash = bcrypt.hashSync(refreshToken, 10);
                const expiresAt = new Date(Date.now() + ms(process.env.REFRESH_TOKEN_EXPIRY)); 
                try {
                        await db.query(
                        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, device_info) VALUES ($1, $2, $3, $4);",
                        [userPayload.id, refreshTokenHash, expiresAt, 'Unknown Device']
                    );
                }catch(err){ 
                    console.error('Error inserting refresh token:', err);
                    return res.status(500).json({ message: "Internal server error while storing refresh token." });
                }
                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    expires: expiresAt
                });
        res.status(200).json({
            message: "Login successful!",
            accessToken,
            user: {
                id: user.user_id,
                username: user.username,
                email: user.email
            }
        });
            } else{
                res.status(401).send({message: "Invalid password!"});
            }
        } else {
            res.status(401).send({message: "Invalid username or email!"});
        }
    } catch(err){
        return res.status(500);
    }
});

// Token Refresh Endpoint
app.post('/token', async (req, res) => {
    const oldRefreshToken = req.cookies.refreshToken;
    if (!oldRefreshToken) {
        return res.status(401).json({ message: 'No refresh token provided.' });
    }
    try {
        const storedRefreshTokenRecordsResult = await db.query(
            `SELECT * FROM refresh_tokens WHERE is_revoked = FALSE AND expires_at > NOW();`
        );
        let storedRecord = null;
    // Iterate through valid tokens and find a hash match
    for (const record of storedRefreshTokenRecordsResult.rows) {
        if (bcrypt.compareSync(oldRefreshToken, record.token_hash)) {
            storedRecord = record;
            break;
        }
    }
    if(!storedRecord) {
        res.clearCookie('refreshToken');
        return res.status(403).json({message : 'Invalid or revoked refresh token. Please log in again.'})
    }

    let decodedPayload;
        try {
            decodedPayload = jwt.verify(oldRefreshToken, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            // If the refresh token itself is invalid (e.g., tampered), revoke it from DB
            await db.query("UPDATE refresh_tokens SET is_revoked = TRUE WHERE token_id = $1;", [storedRecord.token_id]);
            res.clearCookie('refreshToken');
            return res.status(403).json({ message: 'Invalid refresh token signature. Please log in again.' });
        }
        // Ensure the userId from the decoded token matches the one in the stored DB record
        if (decodedPayload.id !== storedRecord.user_id) {
            await db.query("UPDATE refresh_tokens SET is_revoked = TRUE WHERE token_id = $1;", [storedRecord.token_id]);
            res.clearCookie('refreshToken');
            return res.status(403).json({ message: 'Refresh token mismatch. Please log in again.' });
        }
        // Revoke Refresh Token
        await db.query("UPDATE refresh_tokens SET is_revoked = TRUE WHERE token_id = $1;", [storedRecord.token_id]);
        // Generate new access token
        const newUserPayload = { id: decodedPayload.id, username: decodedPayload.username };
        const { accessToken, refreshToken } = generateTokens(newUserPayload);
        const newRefreshTokenHash = bcrypt.hashSync(refreshToken, 10);
        const newExpiresAt = new Date(Date.now() + ms(process.env.REFRESH_TOKEN_EXPIRY));
        await db.query(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, device_info) VALUES ($1, $2, $3, $4);",
            [decodedPayload.id, newRefreshTokenHash, newExpiresAt, storedRecord.device_info]
        );
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            expires: newExpiresAt
        });
        res.status(200).json({ accessToken });
        } catch (err) {
        console.error('Error fetching stored refresh tokens:', err);
        return res.status(500).json({ message: 'Internal server error.' });
    }
});

// Logout Endpoint
app.delete('/logout', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        return res.status(204).send({message: 'Logged Out!'});
    }
    try {
        const storedRefreshTokenRecordsResult = await db.query(
            `SELECT token_id, token_hash FROM refresh_tokens WHERE is_revoked = FALSE;`
        );
        let tokenIdToRevoke = null;
        for (const record of storedRefreshTokenRecordsResult.rows) {
            if (bcrypt.compareSync(refreshToken, record.token_hash)) {
                tokenIdToRevoke = record.token_id;
                break;
            }
        }
        if (tokenIdToRevoke) {
            await db.query("UPDATE refresh_tokens SET is_revoked = TRUE WHERE token_id = $1;", [tokenIdToRevoke]);
        }
        res.clearCookie('refreshToken');
        res.status(204).send();
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Error during logout.' });
    }
});






app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);})