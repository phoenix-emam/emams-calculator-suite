<?php
require_once 'config.php';

// User registration
function registerUser($fullName, $email, $phone, $gender, $dateOfBirth, $password) {
    try {
        $pdo = getDB();
        
        // Check if email already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        
        if ($stmt->rowCount() > 0) {
            return ['success' => false, 'message' => 'Email already exists'];
        }
        
        // Hash password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        // Insert user
        $stmt = $pdo->prepare("
            INSERT INTO users (full_name, email, phone, gender, date_of_birth, password, email_verified, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $result = $stmt->execute([$fullName, $email, $phone, $gender, $dateOfBirth, $hashedPassword, 0, 1]);
        
        if ($result) {
            $userId = $pdo->lastInsertId();
            
            // Log registration
            logActivity($userId, 'User Registration', "User registered with email: $email");
            
            // Get the created user
            $stmt = $pdo->prepare("SELECT id, full_name, email, phone, gender, date_of_birth, is_admin, is_active, created_at FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return ['success' => true, 'message' => 'Registration successful', 'user' => $user];
        } else {
            return ['success' => false, 'message' => 'Registration failed'];
        }
    } catch (PDOException $e) {
        error_log("Database error in registerUser: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    } catch (Exception $e) {
        error_log("General error in registerUser: " . $e->getMessage());
        return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
    }
}

// User login
function loginUser($email, $password, $remember = false) {
    try {
        $pdo = getDB();
        
        // Get user by email
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            return ['success' => false, 'message' => 'Invalid email or password'];
        }
        
        // Check if user is active
        if (!$user['is_active']) {
            return ['success' => false, 'message' => 'Account is deactivated'];
        }
        
        // Verify password
        if (!password_verify($password, $user['password'])) {
            return ['success' => false, 'message' => 'Invalid email or password'];
        }
        
        // Set session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_name'] = $user['full_name'];
        $_SESSION['user_email'] = $user['email'];
        $_SESSION['is_admin'] = $user['is_admin'];
        
        // Handle remember me
        if ($remember) {
            $token = bin2hex(random_bytes(32));
            $expires = date('Y-m-d H:i:s', time() + REMEMBER_LIFETIME);
            
            $stmt = $pdo->prepare("UPDATE users SET remember_token = ?, remember_token_expires = ? WHERE id = ?");
            $stmt->execute([$token, $expires, $user['id']]);
            
            setcookie('remember_token', $token, time() + REMEMBER_LIFETIME, '/', '', isset($_SERVER['HTTPS']), true);
        }
        
        // Remove password from user data before returning
        unset($user['password']);
        unset($user['remember_token']);
        
        // Log login
        logActivity($user['id'], 'User Login', "User logged in with email: $email");
        
        return ['success' => true, 'message' => 'Login successful', 'user' => $user];
    } catch (PDOException $e) {
        error_log("Database error in loginUser: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    } catch (Exception $e) {
        error_log("General error in loginUser: " . $e->getMessage());
        return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
    }
}

// User logout
function logoutUser() {
    try {
        if (isset($_SESSION['user_id'])) {
            logActivity($_SESSION['user_id'], 'User Logout', "User logged out");
        }
        
        // Clear session
        session_unset();
        session_destroy();
        
        // Clear remember token
        if (isset($_COOKIE['remember_token'])) {
            $pdo = getDB();
            $stmt = $pdo->prepare("UPDATE users SET remember_token = NULL, remember_token_expires = NULL WHERE remember_token = ?");
            $stmt->execute([$_COOKIE['remember_token']]);
            
            setcookie('remember_token', '', time() - 3600, '/', '', isset($_SERVER['HTTPS']), true);
        }
        
        return ['success' => true, 'message' => 'Logout successful'];
    } catch (PDOException $e) {
        error_log("Database error in logoutUser: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    } catch (Exception $e) {
        error_log("General error in logoutUser: " . $e->getMessage());
        return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
    }
}

// Check if user is logged in
function isLoggedIn() {
    if (isset($_SESSION['user_id'])) {
        return true;
    }
    
    // Check remember token
    if (isset($_COOKIE['remember_token'])) {
        try {
            $pdo = getDB();
            $stmt = $pdo->prepare("SELECT * FROM users WHERE remember_token = ? AND remember_token_expires > NOW() AND is_active = 1");
            $stmt->execute([$_COOKIE['remember_token']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['full_name'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['is_admin'] = $user['is_admin'];
                
                return true;
            }
        } catch (PDOException $e) {
            error_log("Database error in isLoggedIn: " . $e->getMessage());
            return false;
        }
    }
    
    return false;
}

// Check if user is admin
function isAdmin() {
    return isLoggedIn() && isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1;
}

// Get current user
function getCurrentUser() {
    if (!isLoggedIn()) {
        return null;
    }
    
    try {
        $pdo = getDB();
        $stmt = $pdo->prepare("SELECT id, full_name, email, phone, gender, date_of_birth, special_notes, is_admin, is_active, created_at, updated_at FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database error in getCurrentUser: " . $e->getMessage());
        return null;
    }
}

// Log activity
function logActivity($userId, $action, $details = '') {
    try {
        $pdo = getDB();
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $stmt = $pdo->prepare("
            INSERT INTO audit_trail (user_id, action, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([$userId, $action, $details, $ipAddress, $userAgent]);
    } catch (PDOException $e) {
        error_log("Database error in logActivity: " . $e->getMessage());
    }
}

// Generate password reset token
function generatePasswordResetToken($email) {
    try {
        $pdo = getDB();
        
        // Check if email exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        
        if ($stmt->rowCount() == 0) {
            return ['success' => false, 'message' => 'Email not found'];
        }
        
        // Generate token
        $token = bin2hex(random_bytes(32));
        $expires = date('Y-m-d H:i:s', time() + 3600); // 1 hour
        
        // Delete existing tokens
        $stmt = $pdo->prepare("DELETE FROM password_resets WHERE email = ?");
        $stmt->execute([$email]);
        
        // Insert new token
        $stmt = $pdo->prepare("
            INSERT INTO password_resets (email, token, expires_at)
            VALUES (?, ?, ?)
        ");
        
        $result = $stmt->execute([$email, $token, $expires]);
        
        if ($result) {
            // In a real application, you would send an email with the reset link
            // For this example, we'll just return the token
            $resetLink = APP_URL . "/reset_password.php?token=" . $token;
            
            return [
                'success' => true, 
                'message' => 'Password reset link generated',
                'token' => $token,
                'link' => $resetLink
            ];
        } else {
            return ['success' => false, 'message' => 'Failed to generate reset token'];
        }
    } catch (PDOException $e) {
        error_log("Database error in generatePasswordResetToken: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

// Verify password reset token
function verifyPasswordResetToken($token) {
    try {
        $pdo = getDB();
        
        $stmt = $pdo->prepare("
            SELECT * FROM password_resets 
            WHERE token = ? AND expires_at > NOW()
        ");
        $stmt->execute([$token]);
        
        if ($stmt->rowCount() > 0) {
            $reset = $stmt->fetch(PDO::FETCH_ASSOC);
            return ['success' => true, 'email' => $reset['email']];
        } else {
            return ['success' => false, 'message' => 'Invalid or expired token'];
        }
    } catch (PDOException $e) {
        error_log("Database error in verifyPasswordResetToken: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

// Reset password
function resetPassword($token, $password) {
    try {
        // Verify token
        $verification = verifyPasswordResetToken($token);
        if (!$verification['success']) {
            return $verification;
        }
        
        // Hash new password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        // Update password
        $pdo = getDB();
        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE email = ?");
        $result = $stmt->execute([$hashedPassword, $verification['email']]);
        
        if ($result) {
            // Delete token
            $stmt = $pdo->prepare("DELETE FROM password_resets WHERE token = ?");
            $stmt->execute([$token]);
            
            // Get user ID for logging
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$verification['email']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Log password reset
            logActivity($user['id'], 'Password Reset', "Password reset for email: " . $verification['email']);
            
            return ['success' => true, 'message' => 'Password reset successful'];
        } else {
            return ['success' => false, 'message' => 'Password reset failed'];
        }
    } catch (PDOException $e) {
        error_log("Database error in resetPassword: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

// Update user profile
function updateUserProfile($userId, $fullName, $phone, $gender, $dateOfBirth, $specialNotes) {
    try {
        $pdo = getDB();
        
        $stmt = $pdo->prepare("
            UPDATE users 
            SET full_name = ?, phone = ?, gender = ?, date_of_birth = ?, special_notes = ?, updated_at = NOW()
            WHERE id = ?
        ");
        
        $result = $stmt->execute([$fullName, $phone, $gender, $dateOfBirth, $specialNotes, $userId]);
        
        if ($result) {
            // Update session
            $_SESSION['user_name'] = $fullName;
            
            // Log profile update
            logActivity($userId, 'Profile Update', "User updated profile");
            
            // Get updated user
            $stmt = $pdo->prepare("SELECT id, full_name, email, phone, gender, date_of_birth, special_notes, is_admin, is_active, created_at, updated_at FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return ['success' => true, 'message' => 'Profile updated successfully', 'user' => $user];
        } else {
            return ['success' => false, 'message' => 'Profile update failed'];
        }
    } catch (PDOException $e) {
        error_log("Database error in updateUserProfile: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

// Change password
function changePassword($userId, $currentPassword, $newPassword) {
    try {
        $pdo = getDB();
        
        // Get current password
        $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Verify current password
        if (!password_verify($currentPassword, $user['password'])) {
            return ['success' => false, 'message' => 'Current password is incorrect'];
        }
        
        // Hash new password
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        
        // Update password
        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
        $result = $stmt->execute([$hashedPassword, $userId]);
        
        if ($result) {
            // Log password change
            logActivity($userId, 'Password Change', "User changed password");
            
            return ['success' => true, 'message' => 'Password changed successfully'];
        } else {
            return ['success' => false, 'message' => 'Password change failed'];
        }
    } catch (PDOException $e) {
        error_log("Database error in changePassword: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

// Upload avatar
function uploadAvatar($userId, $file) {
    try {
        // Check if file was uploaded
        if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
            return ['success' => false, 'message' => 'No file uploaded'];
        }
        
        // Check file size
        if ($file['size'] > MAX_FILE_SIZE) {
            return ['success' => false, 'message' => 'File too large'];
        }
        
        // Check file type
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        $fileInfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($fileInfo, $file['tmp_name']);
        finfo_close($fileInfo);
        
        if (!in_array($mimeType, $allowedTypes)) {
            return ['success' => false, 'message' => 'Invalid file type'];
        }
        
        // Create upload directory if it doesn't exist
        if (!is_dir(UPLOAD_PATH)) {
            mkdir(UPLOAD_PATH, 0755, true);
        }
        
        // Generate unique filename
        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        $filename = $userId . '_' . time() . '.' . $extension;
        $filepath = UPLOAD_PATH . $filename;
        
        // Move file
        if (move_uploaded_file($file['tmp_name'], $filepath)) {
            // Update database
            $pdo = getDB();
            $stmt = $pdo->prepare("UPDATE users SET avatar = ? WHERE id = ?");
            $result = $stmt->execute([$filename, $userId]);
            
            if ($result) {
                // Log avatar upload
                logActivity($userId, 'Avatar Upload', "User uploaded avatar: $filename");
                
                return ['success' => true, 'message' => 'Avatar uploaded successfully', 'filename' => $filename];
            } else {
                // Delete file if database update failed
                unlink($filepath);
                return ['success' => false, 'message' => 'Failed to save avatar to database'];
            }
        } else {
            return ['success' => false, 'message' => 'Failed to upload file'];
        }
    } catch (PDOException $e) {
        error_log("Database error in uploadAvatar: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    } catch (Exception $e) {
        error_log("General error in uploadAvatar: " . $e->getMessage());
        return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
    }
}

// Get user activity
function getUserActivity($userId, $limit = 50) {
    try {
        $pdo = getDB();
        
        $stmt = $pdo->prepare("
            SELECT * FROM audit_trail 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
        ");
        $stmt->execute([$userId, $limit]);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database error in getUserActivity: " . $e->getMessage());
        return [];
    }
}

// Get calculator usage statistics
function getCalculatorUsage($userId = null, $calculatorType = null, $limit = 100) {
    try {
        $pdo = getDB();
        
        $sql = "SELECT cu.*, u.full_name FROM calculator_usage cu 
                LEFT JOIN users u ON cu.user_id = u.id 
                WHERE 1=1";
        $params = [];
        
        if ($userId) {
            $sql .= " AND cu.user_id = ?";
            $params[] = $userId;
        }
        
        if ($calculatorType) {
            $sql .= " AND cu.calculator_type = ?";
            $params[] = $calculatorType;
        }
        
        $sql .= " ORDER BY cu.created_at DESC LIMIT ?";
        $params[] = $limit;
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database error in getCalculatorUsage: " . $e->getMessage());
        return [];
    }
}

// Log calculator usage
function logCalculatorUsage($calculatorType, $operation, $result) {
    try {
        if (isLoggedIn()) {
            $pdo = getDB();
            
            $stmt = $pdo->prepare("
                INSERT INTO calculator_usage (user_id, calculator_type, operation, result)
                VALUES (?, ?, ?, ?)
            ");
            
            $stmt->execute([$_SESSION['user_id'], $calculatorType, $operation, $result]);
        }
    } catch (PDOException $e) {
        error_log("Database error in logCalculatorUsage: " . $e->getMessage());
    }
}
?>