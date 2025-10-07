<?php
require_once 'config.php';
require_once 'auth.php';

header('Content-Type: application/json');

// Get the request method
 $method = $_SERVER['REQUEST_METHOD'];

// Get the endpoint
 $endpoint = isset($_GET['endpoint']) ? $_GET['endpoint'] : '';

// Handle the request
switch ($endpoint) {
    case 'register':
        handleRegister();
        break;
    case 'login':
        handleLogin();
        break;
    case 'logout':
        handleLogout();
        break;
    case 'forgot_password':
        handleForgotPassword();
        break;
    case 'reset_password':
        handleResetPassword();
        break;
    case 'update_profile':
        handleUpdateProfile();
        break;
    case 'change_password':
        handleChangePassword();
        break;
    case 'upload_avatar':
        handleUploadAvatar();
        break;
    case 'get_user':
        handleGetUser();
        break;
    case 'get_users':
        handleGetUsers();
        break;
    case 'update_user':
        handleUpdateUser();
        break;
    case 'delete_user':
        handleDeleteUser();
        break;
    case 'get_activities':
        handleGetActivities();
        break;
    case 'log_calculator_usage':
        handleLogCalculatorUsage();
        break;
    case 'get_calculator_usage':
        handleGetCalculatorUsage();
        break;
    case 'update_settings':
        handleUpdateSettings();
        break;
    case 'get_settings':
        handleGetSettings();
        break;
    default:
        sendResponse(['success' => false, 'message' => 'Invalid endpoint'], 404);
        break;
}

function handleRegister() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    $fullName = $data['full_name'] ?? '';
    $email = $data['email'] ?? '';
    $countryCode = $data['country_code'] ?? '';
    $phone = $data['phone'] ?? '';
    $gender = $data['gender'] ?? '';
    $dateOfBirth = $data['date_of_birth'] ?? '';
    $password = $data['password'] ?? '';
    
    // Combine country code and phone
    $fullPhone = $countryCode . $phone;
    
    $result = registerUser($fullName, $email, $fullPhone, $gender, $dateOfBirth, $password);
    sendResponse($result);
}

function handleLogin() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    $email = $data['email'] ?? '';
    $password = $data['password'] ?? '';
    $remember = $data['remember'] ?? false;
    
    $result = loginUser($email, $password, $remember);
    sendResponse($result);
}

function handleLogout() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    $result = logoutUser();
    sendResponse($result);
}

function handleForgotPassword() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    $email = $data['email'] ?? '';
    
    $result = generatePasswordResetToken($email);
    sendResponse($result);
}

function handleResetPassword() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    $token = $data['token'] ?? '';
    $password = $data['password'] ?? '';
    
    $result = resetPassword($token, $password);
    sendResponse($result);
}

function handleUpdateProfile() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    if (!isLoggedIn()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    $fullName = $data['full_name'] ?? '';
    $phone = $data['phone'] ?? '';
    $gender = $data['gender'] ?? '';
    $dateOfBirth = $data['date_of_birth'] ?? '';
    $specialNotes = $data['special_notes'] ?? '';
    
    $userId = $_SESSION['user_id'];
    $result = updateUserProfile($userId, $fullName, $phone, $gender, $dateOfBirth, $specialNotes);
    sendResponse($result);
}

function handleChangePassword() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    if (!isLoggedIn()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    $currentPassword = $data['current_password'] ?? '';
    $newPassword = $data['new_password'] ?? '';
    
    $userId = $_SESSION['user_id'];
    $result = changePassword($userId, $currentPassword, $newPassword);
    sendResponse($result);
}

function handleUploadAvatar() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    if (!isLoggedIn()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    $userId = $_SESSION['user_id'];
    $result = uploadAvatar($userId, $_FILES['avatar']);
    sendResponse($result);
}

function handleGetUser() {
    if (!isLoggedIn()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    $user = getCurrentUser();
    sendResponse(['success' => true, 'user' => $user]);
}

function handleGetUsers() {
    if (!isAdmin()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    try {
        $pdo = getDB();
        
        // Get pagination parameters
        $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
        $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
        $offset = ($page - 1) * $limit;
        
        // Get search and filter parameters
        $search = isset($_GET['search']) ? $_GET['search'] : '';
        $status = isset($_GET['status']) ? $_GET['status'] : '';
        $role = isset($_GET['role']) ? $_GET['role'] : '';
        
        // Build query
        $query = "SELECT id, full_name, email, phone, gender, date_of_birth, is_active, is_admin, created_at, updated_at FROM users WHERE 1=1";
        $params = [];
        
        if (!empty($search)) {
            $query .= " AND (full_name LIKE ? OR email LIKE ?)";
            $params[] = "%$search%";
            $params[] = "%$search%";
        }
        
        if (!empty($status)) {
            $query .= " AND is_active = ?";
            $params[] = $status === 'active' ? 1 : 0;
        }
        
        if (!empty($role)) {
            $query .= " AND is_admin = ?";
            $params[] = $role === 'admin' ? 1 : 0;
        }
        
        // Get total count
        $countQuery = "SELECT COUNT(*) FROM users WHERE 1=1";
        $countParams = [];
        
        if (!empty($search)) {
            $countQuery .= " AND (full_name LIKE ? OR email LIKE ?)";
            $countParams[] = "%$search%";
            $countParams[] = "%$search%";
        }
        
        if (!empty($status)) {
            $countQuery .= " AND is_active = ?";
            $countParams[] = $status === 'active' ? 1 : 0;
        }
        
        if (!empty($role)) {
            $countQuery .= " AND is_admin = ?";
            $countParams[] = $role === 'admin' ? 1 : 0;
        }
        
        $stmt = $pdo->prepare($countQuery);
        $stmt->execute($countParams);
        $total = $stmt->fetchColumn();
        
        // Get users
        $query .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;
        
        $stmt = $pdo->prepare($query);
        $stmt->execute($params);
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        sendResponse([
            'success' => true,
            'users' => $users,
            'pagination' => [
                'page' => $page,
                'limit' => $limit,
                'total' => $total,
                'pages' => ceil($total / $limit)
            ]
        ]);
    } catch (PDOException $e) {
        error_log("Database error in handleGetUsers: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
        error_log("General error in handleGetUsers: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function handleUpdateUser() {
    if (!isAdmin()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        
        $userId = $data['user_id'] ?? '';
        $fullName = $data['full_name'] ?? '';
        $email = $data['email'] ?? '';
        $phone = $data['phone'] ?? '';
        $gender = $data['gender'] ?? '';
        $dateOfBirth = $data['date_of_birth'] ?? '';
        $isActive = $data['is_active'] ?? true;
        $isAdmin = $data['is_admin'] ?? false;
        
        $pdo = getDB();
        
        // Check if user exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        
        if ($stmt->rowCount() === 0) {
            sendResponse(['success' => false, 'message' => 'User not found']);
            return;
        }
        
        // Update user
        $stmt = $pdo->prepare("
            UPDATE users 
            SET full_name = ?, email = ?, phone = ?, gender = ?, date_of_birth = ?, is_active = ?, is_admin = ?, updated_at = NOW()
            WHERE id = ?
        ");
        
        $result = $stmt->execute([$fullName, $email, $phone, $gender, $dateOfBirth, $isActive, $isAdmin, $userId]);
        
        if ($result) {
            // Log activity
            logActivity($_SESSION['user_id'], 'User Update', "Updated user with ID: $userId");
            
            sendResponse(['success' => true, 'message' => 'User updated successfully']);
        } else {
            sendResponse(['success' => false, 'message' => 'Failed to update user']);
        }
    } catch (PDOException $e) {
        error_log("Database error in handleUpdateUser: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
        error_log("General error in handleUpdateUser: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function handleDeleteUser() {
    if (!isAdmin()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        
        $userId = $data['user_id'] ?? '';
        
        $pdo = getDB();
        
        // Check if user exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        
        if ($stmt->rowCount() === 0) {
            sendResponse(['success' => false, 'message' => 'User not found']);
            return;
        }
        
        // Delete user
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $result = $stmt->execute([$userId]);
        
        if ($result) {
            // Log activity
            logActivity($_SESSION['user_id'], 'User Deletion', "Deleted user with ID: $userId");
            
            sendResponse(['success' => true, 'message' => 'User deleted successfully']);
        } else {
            sendResponse(['success' => false, 'message' => 'Failed to delete user']);
        }
    } catch (PDOException $e) {
        error_log("Database error in handleDeleteUser: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
        error_log("General error in handleDeleteUser: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function handleGetActivities() {
    if (!isAdmin()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    try {
        $pdo = getDB();
        
        // Get pagination parameters
        $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
        $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
        $offset = ($page - 1) * $limit;
        
        // Get filter parameters
        $user = isset($_GET['user']) ? $_GET['user'] : '';
        $action = isset($_GET['action']) ? $_GET['action'] : '';
        $fromDate = isset($_GET['from_date']) ? $_GET['from_date'] : '';
        $toDate = isset($_GET['to_date']) ? $_GET['to_date'] : '';
        
        // Build query
        $query = "
            SELECT a.*, u.full_name 
            FROM audit_trail a 
            LEFT JOIN users u ON a.user_id = u.id 
            WHERE 1=1
        ";
        $params = [];
        
        if (!empty($user)) {
            $query .= " AND u.full_name LIKE ?";
            $params[] = "%$user%";
        }
        
        if (!empty($action)) {
            $query .= " AND a.action LIKE ?";
            $params[] = "%$action%";
        }
        
        if (!empty($fromDate)) {
            $query .= " AND DATE(a.created_at) >= ?";
            $params[] = $fromDate;
        }
        
        if (!empty($toDate)) {
            $query .= " AND DATE(a.created_at) <= ?";
            $params[] = $toDate;
        }
        
        // Get total count
        $countQuery = "SELECT COUNT(*) FROM audit_trail a LEFT JOIN users u ON a.user_id = u.id WHERE 1=1";
        $countParams = [];
        
        if (!empty($user)) {
            $countQuery .= " AND u.full_name LIKE ?";
            $countParams[] = "%$user%";
        }
        
        if (!empty($action)) {
            $countQuery .= " AND a.action LIKE ?";
            $countParams[] = "%$action%";
        }
        
        if (!empty($fromDate)) {
            $countQuery .= " AND DATE(a.created_at) >= ?";
            $countParams[] = $fromDate;
        }
        
        if (!empty($toDate)) {
            $countQuery .= " AND DATE(a.created_at) <= ?";
            $countParams[] = $toDate;
        }
        
        $stmt = $pdo->prepare($countQuery);
        $stmt->execute($countParams);
        $total = $stmt->fetchColumn();
        
        // Get activities
        $query .= " ORDER BY a.created_at DESC LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;
        
        $stmt = $pdo->prepare($query);
        $stmt->execute($params);
        $activities = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        sendResponse([
            'success' => true,
            'activities' => $activities,
            'pagination' => [
                'page' => $page,
                'limit' => $limit,
                'total' => $total,
                'pages' => ceil($total / $limit)
            ]
        ]);
    } catch (PDOException $e) {
        error_log("Database error in handleGetActivities: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
        error_log("General error in handleGetActivities: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function handleLogCalculatorUsage() {
    if (!isLoggedIn()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        
        $calculatorType = $data['calculator_type'] ?? '';
        $operation = $data['operation'] ?? '';
        $result = $data['result'] ?? '';
        
        $userId = $_SESSION['user_id'];
        logCalculatorUsage($calculatorType, $operation, $result);
        
        sendResponse(['success' => true, 'message' => 'Calculator usage logged successfully']);
    } catch (Exception $e) {
        error_log("Error in handleLogCalculatorUsage: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function handleGetCalculatorUsage() {
    if (!isLoggedIn()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    try {
        $pdo = getDB();
        
        // Get user's calculator usage
        $userId = $_SESSION['user_id'];
        $stmt = $pdo->prepare("
            SELECT calculator_type, operation, result, created_at 
            FROM calculator_usage 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 50
        ");
        $stmt->execute([$userId]);
        $calculations = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        sendResponse([
            'success' => true,
            'calculations' => $calculations
        ]);
    } catch (PDOException $e) {
        error_log("Database error in handleGetCalculatorUsage: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
        error_log("General error in handleGetCalculatorUsage: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function handleUpdateSettings() {
    if (!isLoggedIn()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(['success' => false, 'message' => 'Method not allowed'], 405);
        return;
    }
    
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        $userId = $_SESSION['user_id'];
        
        $pdo = getDB();
        
        // Check if settings exist for user
        $stmt = $pdo->prepare("SELECT user_id FROM user_settings WHERE user_id = ?");
        $stmt->execute([$userId]);
        
        if ($stmt->rowCount() > 0) {
            // Update existing settings
            $stmt = $pdo->prepare("
                UPDATE user_settings 
                SET theme = ?, notifications = ?, language = ?, timezone = ?, auto_save = ?
                WHERE user_id = ?
            ");
            $result = $stmt->execute([
                $data['theme'] ?? 'light',
                $data['notifications'] ?? 1,
                $data['language'] ?? 'en',
                $data['timezone'] ?? 'UTC',
                $data['auto_save'] ?? 1,
                $userId
            ]);
        } else {
            // Insert new settings
            $stmt = $pdo->prepare("
                INSERT INTO user_settings 
                (user_id, theme, notifications, language, timezone, auto_save)
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            $result = $stmt->execute([
                $userId,
                $data['theme'] ?? 'light',
                $data['notifications'] ?? 1,
                $data['language'] ?? 'en',
                $data['timezone'] ?? 'UTC',
                $data['auto_save'] ?? 1
            ]);
        }
        
        if ($result) {
            logActivity($userId, 'Settings Update', "User updated settings");
            sendResponse(['success' => true, 'message' => 'Settings updated successfully']);
        } else {
            sendResponse(['success' => false, 'message' => 'Failed to update settings']);
        }
    } catch (PDOException $e) {
        error_log("Database error in handleUpdateSettings: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
        error_log("General error in handleUpdateSettings: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function handleGetSettings() {
    if (!isLoggedIn()) {
        sendResponse(['success' => false, 'message' => 'Unauthorized'], 401);
        return;
    }
    
    try {
        $userId = $_SESSION['user_id'];
        $pdo = getDB();
        
        $stmt = $pdo->prepare("SELECT * FROM user_settings WHERE user_id = ?");
        $stmt->execute([$userId]);
        $settings = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$settings) {
            // Return default settings if none exist
            $settings = [
                'theme' => 'light',
                'notifications' => 1,
                'language' => 'en',
                'timezone' => 'UTC',
                'auto_save' => 1
            ];
        }
        
        sendResponse(['success' => true, 'settings' => $settings]);
    } catch (PDOException $e) {
        error_log("Database error in handleGetSettings: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
        error_log("General error in handleGetSettings: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
    }
}

function sendResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    echo json_encode($data);
    exit;
}
?>