package com.studentlink.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.studentlink.dto.LoginRequest;
import com.studentlink.dto.RegisterRequest;
import com.studentlink.dto.AuthResponse;
import com.studentlink.model.User;
import com.studentlink.model.Role;
import com.studentlink.repository.UserRepository;
import com.studentlink.security.JwtUtil;


@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;

    // ✅ MANUAL CONSTRUCTOR (replaces Lombok)
    public AuthService(UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            EmailService emailService) {

    	this.userRepository = userRepository;
    	this.passwordEncoder = passwordEncoder;
    	this.jwtUtil = jwtUtil;
    	this.emailService = emailService;
}

    // 🔹 REGISTER
    public AuthResponse register(RegisterRequest request) {

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.STUDENT);

        // 🔐 Generate OTP
        String otp = String.valueOf((int)(Math.random() * 900000) + 100000);

        user.setOtp(otp);
        user.setEmailVerified(false);

        userRepository.save(user);

        // 📧 Send OTP email
        emailService.sendOtp(user.getEmail(), otp);

        return new AuthResponse("OTP sent to email");
    }
    // 🔹 LOGIN
    public AuthResponse login(LoginRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        // 🚫 BLOCK if email not verified
        if (!user.isEmailVerified()) {
            throw new RuntimeException("Please verify your email first");
        }

        String token = jwtUtil.generateToken(user.getEmail());
        return new AuthResponse(token);
    }
    
    public AuthResponse verifyOtp(VerifyOtpRequest request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getOtp().equals(request.getOtp())) {

            user.setEmailVerified(true);
            user.setOtp(null);

            userRepository.save(user);

            String token = jwtUtil.generateToken(user.getEmail());
            return new AuthResponse(token);

        } else {
            throw new RuntimeException("Invalid OTP");
        }
    }
}