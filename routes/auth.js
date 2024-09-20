const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const auth = require('../middleware/auth');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

const otpRateLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 15 minutes
    max: 2, // Limit each IP to 3 OTP requests per window
    message: 'Too many OTP requests from this IP, please try again after 15 minutes',
});

// OTP Rate Limiter for Resend OTP
const otpResendRateLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 15 minutes
    max: 2, // Limit each IP to 3 OTP resend requests per window
    message: 'Too many OTP resend requests from this IP, please try again after 15 minutes',
});

// Generate a random 6-digit OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Send OTP to user's email
const sendOTPEmail = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail', // You can use any email provider
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your OTP for Password Change',
        html: `
            <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #ffffff; border-radius: 10px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);">
                <h2 style="color: #4CAF50; text-align: center; margin-bottom: 30px;">🔒 Password Change Request</h2>
                <p style="font-size: 16px; color: #333; margin-bottom: 20px;">Dear User,</p>
                <p style="font-size: 16px; color: #555; margin-bottom: 30px;">
                    You have requested to change your password. Please use the following One-Time Password (OTP) to verify your identity and proceed with the password change:
                </p>
                <div style="text-align: center; margin-bottom: 30px;">
                    <span style="font-size: 28px; font-weight: bold; padding: 10px 20px; background-color: #4CAF50; color: #ffffff; border-radius: 5px; letter-spacing: 2px; display: inline-block;">
                        ${otp}
                    </span>
                </div>
                <p style="font-size: 16px; color: #555; text-align: center; margin-bottom: 30px;">
                    This OTP is valid for <strong>5 minutes</strong>.
                </p>
                <p style="font-size: 16px; color: #777; text-align: center; margin-bottom: 30px;">
                    If you did not request this change, please ignore this email or contact our support team.
                </p>
                <hr style="border: none; border-top: 1px solid #eee; margin-bottom: 20px;">
                <p style="font-size: 14px; color: #999; text-align: center;">
                    Best regards,<br>
                    <strong>Your Company Name</strong><br>
                    <a href="https://yourwebsite.com" style="color: #4CAF50; text-decoration: none;">www.yourwebsite.com</a>
                </p>
            </div>
        `
    };

    await transporter.sendMail(mailOptions);
};

// Resend OTP to user's email
const resendOTPEmail = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail', // You can use any email provider
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your OTP for Password Change (Resend)',
        html: `
            <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #ffffff; border-radius: 10px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);">
                <h2 style="color: #4CAF50; text-align: center; margin-bottom: 30px;">🔄 Resend OTP Request</h2>
                <p style="font-size: 16px; color: #333; margin-bottom: 20px;">Dear User,</p>
                <p style="font-size: 16px; color: #555; margin-bottom: 30px;">
                    As per your request, we have resent the OTP for your password change. Please use the following One-Time Password (OTP) to verify your identity:
                </p>
                <div style="text-align: center; margin-bottom: 30px;">
                    <span style="font-size: 28px; font-weight: bold; padding: 10px 20px; background-color: #4CAF50; color: #ffffff; border-radius: 5px; letter-spacing: 2px; display: inline-block;">
                        ${otp}
                    </span>
                </div>
                <p style="font-size: 16px; color: #555; text-align: center; margin-bottom: 30px;">
                    This OTP is valid for <strong>5 minutes</strong>.
                </p>
                <p style="font-size: 16px; color: #777; text-align: center; margin-bottom: 30px;">
                    If you did not request this OTP, please ignore this email or contact our support team.
                </p>
                <hr style="border: none; border-top: 1px solid #eee; margin-bottom: 20px;">
                <p style="font-size: 14px; color: #999; text-align: center;">
                    Best regards,<br>
                    <strong>Your Company Name</strong><br>
                    <a href="https://yourwebsite.com" style="color: #4CAF50; text-decoration: none;">www.yourwebsite.com</a>
                </p>
            </div>
        `
    };

    await transporter.sendMail(mailOptions);
};
// send OTP to user's email for password reset
const sendOTPEmailForReset = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail', // You can use any email provider
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your OTP for Password Reset',
        html: `
            <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #ffffff; border-radius: 10px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);">
                <h2 style="color: #4CAF50; text-align: center; margin-bottom: 30px;">🔑 Password Reset Request</h2>
                <p style="font-size: 16px; color: #333; margin-bottom: 20px;">Dear User,</p>
                <p style="font-size: 16px; color: #555; margin-bottom: 30px;">
                    We received a request to reset your password. Please use the following One-Time Password (OTP) to reset your account password:
                </p>
                <div style="text-align: center; margin-bottom: 30px;">
                    <span style="font-size: 28px; font-weight: bold; padding: 10px 20px; background-color: #4CAF50; color: #ffffff; border-radius: 5px; letter-spacing: 2px; display: inline-block;">
                        ${otp}
                    </span>
                </div>
                <p style="font-size: 16px; color: #555; text-align: center; margin-bottom: 30px;">
                    This OTP is valid for <strong>5 minutes</strong>.
                </p>
                <p style="font-size: 16px; color: #777; text-align: center; margin-bottom: 30px;">
                    If you did not request a password reset, please ignore this email or contact our support team.
                </p>
                <hr style="border: none; border-top: 1px solid #eee; margin-bottom: 20px;">
                <p style="font-size: 14px; color: #999; text-align: center;">
                    Best regards,<br>
                    <strong>Your Company Name</strong><br>
                    <a href="https://yourwebsite.com" style="color: #4CAF50; text-decoration: none;">www.yourwebsite.com</a>
                </p>
            </div>
        `,
    };

    await transporter.sendMail(mailOptions);
};


// Register a new user
router.post(
    '/register',
    [
        check('username', 'Username is required').not().isEmpty().isLowercase().isAlphanumeric(), // Check for alphanumeric username
        check('name', 'Name is required').not().isEmpty(), // Check for name, not email
        check('email', 'Please include a valid email').isEmail(), // Correct email validation
        check('password', 'Password should be 6 or more characters').isLength({ min: 6 }), // Password length validation
        check('phone', 'Phone number should be 10 digits').isLength({ min: 10, max: 10 }), // Phone length validation
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { username, name, email, password, phone } = req.body;
        try {
            // Check if username already exists
            let user = await User.findOne({ username });
            if (user) return res.status(400).json({ msg: 'Username already exists, try another one!' });

            // Check if email already exists
            user = await User.findOne({ email });
            if (user) return res.status(400).json({ msg: 'User with this email already exists!' });

            // Check if name already exists
            user = await User.findOne({ name });
            if (user) return res.status(400).json({ msg: 'User with this Name already exists!' });

            // Check if phone number already exists
            user = await User.findOne({ phone });
            if (user) return res.status(400).json({ msg: 'User with this phone number already exists!' });

            // Create new user
            user = new User({ username, name, email, password, phone });
            await user.save();

            // Generate JWT token
            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.json({ token });
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }
    }
);


// Login user
router.post(
    '/login',
    [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password is required').exists(),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { email, password } = req.body;
        try {
            const user = await User.findOne({ email });
            if (!user) return res.status(400).json({ msg: 'Invalid credentials, Enter a Valid Email!' });

            const isMatch = await user.matchPassword(password);
            if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials, Enter a Valid Password' });

            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.json({ token , msg:'Logined Successfully!'});
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }
    }
);



// Request OTP for password change
router.post('/request-change-password', otpRateLimiter, auth, async (req, res) => {
    try {
        // Look up the user by ID
        const user = await User.findById(req.user.id);
        console.log(user);

        if (!user) return res.status(404).json({ msg: 'User not found' });

        // Check if OTP was recently generated (within the last 10 minutes)
        if (user.otpExpires && user.otpExpires > Date.now()) {
            return res.status(400).json({ msg: 'You have already requested an OTP. Please wait 10 minutes before requesting a new one.' });
        }

        // Generate OTP and save it temporarily
        const otp = generateOTP();
        user.otp = otp;  // Store OTP in the User model
        user.otpExpires = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes
        await user.save();

        // Send OTP via email
        await sendOTPEmail(user.email, otp);
        res.json({ msg: 'OTP sent to your email' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});



// Change password with OTP verification
router.put('/change-password', auth, async (req, res) => {
    const { oldPassword, newPassword, otp } = req.body;
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ msg: 'User not found' });

        // Verify OTP
        if (!user.otp || user.isOTPExpired()) {
            return res.status(400).json({ msg: 'OTP has expired' });
        }
        if (otp !== user.otp) {
            return res.status(400).json({ msg: 'Invalid OTP' });
        }
        // Verify old password
        const isMatch = await user.matchPassword(oldPassword);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid current password' });

        // Check if the new password is the same as the current password
        const isMatchCurrentP = await user.matchPassword(newPassword);
        if (isMatchCurrentP) return res.status(400).json({ msg: 'New password cannot be the same as the current password. Please choose a different one.' });


        // Hash new password and update
        user.password = newPassword;
        user.otp = undefined; // Clear OTP
        user.otpExpires = undefined; // Clear OTP expiration

        // Rehash the password before saving (due to pre('save') hook)
        await user.save();

        res.json({ msg: 'Password updated successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Resend OTP Route
router.post('/resend-otp', otpResendRateLimiter, auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ msg: 'User not found' });

        // Generate a new OTP and save it temporarily
        const newOtp = generateOTP();
        user.otp = newOtp;
        user.otpExpires = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes
        await user.save();

        // Send new OTP via email
        await resendOTPEmail(user.email, newOtp);
        res.json({ msg: 'New OTP sent to your email' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});



// Delete User Route
router.delete('/delete-user', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ msg: 'User not found' });

        // Delete the user from the database
        await user.remove();

        res.json({ msg: 'User deleted successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});






// Update user details (username, phone, email, name)
router.put(
    '/update-details',
    auth,
    [
        check('username', 'Username is required').optional().not().isEmpty().isLowercase().isAlphanumeric(), // Validate username
        check('username', 'Username is Must in lowerCase').optional().not().isEmpty().isLowercase().isAlphanumeric(), // Validate username
        check('name', 'Name is required').optional().not().isEmpty(), // Validate name
        check('email', 'Please include a valid email').optional().isEmail(), // Validate email
        check('phone', 'Phone number should be 10 digits').optional().isLength({ min: 10, max: 10 }), // Validate phone
    ],
    async (req, res) => {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, phone, email, name } = req.body;
        try {
            // Fetch the user to be updated
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ msg: 'User not found' });
            }

            // Check if the new username is being updated and already exists
            if (username && username !== user.username) {
                const usernameExists = await User.findOne({ username });
                if (usernameExists) {
                    return res.status(400).json({ msg: 'Username is already in use' });
                }
            }

            // Check if the new name is being updated and already exists
            if (name && name !== user.name) {
                const nameExists = await User.findOne({ name });
                if (nameExists) {
                    return res.status(400).json({ msg: 'Name is already in use' });
                }
            }

            // Check if the new email is being updated and already exists
            if (email && email !== user.email) {
                const emailExists = await User.findOne({ email });
                if (emailExists) {
                    return res.status(400).json({ msg: 'Email is already in use' });
                }
            }

            // Check if the new phone number is being updated and already exists
            if (phone && phone !== user.phone) {
                const phoneExists = await User.findOne({ phone });
                if (phoneExists) {
                    return res.status(400).json({ msg: 'Phone number is already in use' });
                }
            }

            // Proceed with updating the fields if no conflicts
            if (username) user.username = username;
            if (name) user.name = name;
            if (phone) user.phone = phone;
            if (email) user.email = email;

            // Save the updated user
            await user.save();

            res.json({ msg: 'User details updated successfully' });
            console.log(user);

        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }
    }
);

// ForGet Password (reset Password With OTP)
router.post('/forget-pass-word', async(req,res)=>{

    const {email} = req.body

    try {
        const user = await User.findOne({email})
        if (!user) return res.status(404).json({ msg: 'User not found' });


        // Generate OTP and save it temporarily
        const otp = generateOTP();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes
        await user.save();

       // Send OTP via email
        await sendOTPEmailForReset(user.email, otp);
        res.json({ msg: 'OTP sent to your email for password reset' }); 
        
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
    
})

router.put('/reset-password',async (req,res)=>{
    const {email, newPassword ,otp} = req.body;

    try {
        // Look for The User With Email
        const user = await User.findOne({email})
        if(!user) return res.status(404).json({ msg:" User Not Found "})

        // Verify The OTP
        if (!user.otp || user.isOTPExpired()){
            return res.status(400).json({msg:"OTP Has Expired"})
        }

        // is Otp Vaild
        if(otp !== user.otp){
            return res.status(400).json({msg:"Invalid OTP"})
        }
         // Ensure new password is not the same as the current one

        // const isMatch = await user.matchPassword(newPassword);
        // if(!isMatch){
        //     return res.status(400).json({msg:"New password cannot be the same as the current password."})
        // }
        
        // Update Password 
        user.password = newPassword
        user.otp = undefined // Clearing Otp From DB
        user.otpExpires = undefined // Clearing Otp Expiration From DB

        // Rehash The New Password Before Saving 
        await user.save();
        res.json({msg:"Password Reset Successfully"})


    } catch (err) {
        
    }
    console.log(email  , newPassword ,otp);
    
})



// Get user details

router.get('/get-user-details', auth, async (req, res) => {
    try {
        // Fetch the user based on the ID from the token
        const user = await User.findById(req.user.id).select('-password');  // Exclude password from the response


        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        // Send the user details as a response
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});



module.exports = router;
