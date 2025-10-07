<?php
  header('Content-Type: application/json');
  header('Access-Control-Allow-Origin: *');

  if (session_status() === PHP_SESSION_NONE) {
    session_start();
  }

  if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    exit(0);
  }

  include 'connection-pdo.php';
  include 'email-config.php';

  // Helper: send in-app notifications to all admins
  if (!function_exists('notifyAdmins')) {
    function notifyAdmins($conn, $type, $message, $actorUserId = null) {
      try {
        $sel = $conn->prepare("SELECT employee_id FROM tblusers WHERE role = 'admin' AND employee_id IS NOT NULL AND employee_id > 0");
        $sel->execute();
        $ids = $sel->fetchAll(PDO::FETCH_COLUMN) ?: [];
        if (!$ids) { return 0; }
        $ins = $conn->prepare("INSERT INTO tblnotifications (employee_id, type, message, actor_user_id, created_at) VALUES (:eid, :type, :message, :actor, NOW())");
        $ins->bindParam(':type', $type);
        $ins->bindParam(':message', $message);
        if ($actorUserId !== null) { $ins->bindParam(':actor', $actorUserId, PDO::PARAM_INT); }
        else { $ins->bindValue(':actor', null, PDO::PARAM_NULL); }
        $count = 0;
        foreach ($ids as $eid) {
          $eid = (int)$eid; if (!$eid) continue;
          $ins->bindValue(':eid', $eid, PDO::PARAM_INT);
          try { if ($ins->execute()) { $count++; } } catch (Exception $e) { /* ignore individual insert errors */ }
        }
        return $count;
      } catch (Exception $e) { return 0; }
    }
  }

  ensureAdminUser($conn);
  ensureHrUser($conn);

  $operation = '';
  $json = '';
  if ($_SERVER['REQUEST_METHOD'] == 'GET'){
    $operation = isset($_GET['operation']) ? $_GET['operation'] : '';
  } else if($_SERVER['REQUEST_METHOD'] == 'POST'){
    $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
    $json = isset($_POST['json']) ? $_POST['json'] : '';
  }

  switch ($operation) {
    case 'login':
      echo login($conn, $json);
      break;
    case 'me':
      echo me();
      break;
    case 'logout':
      echo logout();
      break;
    case 'updateProfile':
      echo updateProfile($conn, $json);
      break;
    case 'forgotPassword':
      echo forgotPassword($conn, $json);
      break;
    case 'resetPassword':
      echo resetPassword($conn, $json);
      break;
    case 'getCaptcha':
      echo getCaptcha();
      break;
    default:
      echo json_encode(['success' => 0, 'message' => 'Invalid operation']);
  }

  /**
   * ENSURE DEFAULT ADMIN USER EXISTS
   * Creates admin user if not found in database
   * Used for system initialization
   */
  function ensureAdminUser($conn){
    try {
              $stmt = $conn->prepare("SELECT user_id FROM tblusers WHERE username = 'admin' LIMIT 1");
      $stmt->execute();
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      if (!$row) {
        $hash = password_hash('admin123', PASSWORD_DEFAULT);
        $ins = $conn->prepare("INSERT INTO tblusers(username, password, role) VALUES('admin', :password, 'admin')");
        $ins->bindParam(':password', $hash);
        $ins->execute();
      }
    } catch (Exception $e) {
      // ignore seeding errors
    }
  }

  /**
   * ENSURE DEFAULT HR USER EXISTS
   * Creates HR user if not found in database
   * Used for system initialization
   */
  function ensureHrUser($conn){
    try {
              $stmt = $conn->prepare("SELECT user_id FROM tblusers WHERE username = 'hr' LIMIT 1");
      $stmt->execute();
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      if (!$row) {
        $hash = password_hash('hr123', PASSWORD_DEFAULT);
        $ins = $conn->prepare("INSERT INTO tblusers(username, password, role) VALUES('hr', :password, 'hr')");
        $ins->bindParam(':password', $hash);
        $ins->execute();
      }
    } catch (Exception $e) {
      // ignore seeding errors
    }
  }

  /**
   * GET SYSTEM CONFIGURATION SETTING
   * Retrieves setting value from system settings table
   * Returns default value if setting not found
   */
  function getSystemSetting($conn, $key, $default = null){
    try {
      $stmt = $conn->prepare('SELECT setting_value FROM tblsystem_settings WHERE setting_key = :k LIMIT 1');
      $stmt->bindParam(':k', $key);
      $stmt->execute();
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      if ($row && isset($row['setting_value'])) return $row['setting_value'];
    } catch (Exception $e) {}
    return $default;
  }

  /**
   * CHECK SESSION TIMEOUT AND REFRESH
   * Validates session expiry based on system settings
   * Automatically destroys expired sessions with audit logging
   */
  function checkAndRefreshSession($conn) {
    // Returns ['expired' => bool, 'timeout_minutes' => int]
    $mins = intval(getSystemSetting($conn, 'session_timeout_minutes', 30));
    if (!isset($_SESSION['user_id'])) {
      return ['expired' => false, 'timeout_minutes' => $mins];
    }
    if ($mins <= 0) {
      // No timeout enforced; refresh activity timestamp
      $_SESSION['last_activity'] = time();
      return ['expired' => false, 'timeout_minutes' => $mins];
    }
    $now = time();
    $last = isset($_SESSION['last_activity']) ? intval($_SESSION['last_activity']) : $now;
    if (($now - $last) > ($mins * 60)) {
      // Log timeout
      try {
        $uid = isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : null;
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $stmt = $conn->prepare("INSERT INTO tblaudit_logs (user_id, action, details, ip_address) VALUES (:uid, 'session_timeout', 'Session timed out due to inactivity', :ip)");
        if ($uid) { $stmt->bindParam(':uid', $uid, PDO::PARAM_INT); } else { $stmt->bindValue(':uid', null, PDO::PARAM_NULL); }
        $stmt->bindParam(':ip', $ip);
        $stmt->execute();
      } catch (Exception $e) { /* ignore logging errors */ }
      // Destroy session
      $_SESSION = [];
      if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
          $params['path'], $params['domain'],
          $params['secure'], $params['httponly']
        );
      }
      session_destroy();
      return ['expired' => true, 'timeout_minutes' => $mins];
    }
    // Still active; refresh timestamp
    $_SESSION['last_activity'] = $now;
    return ['expired' => false, 'timeout_minutes' => $mins];
  }

  /**
   * GENERATE CAPTCHA FOR SECURITY
   * Creates numeric captcha and stores in session
   * Used for login security validation
   */
  function getCaptcha(){
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    $len = 6;
    if (isset($_REQUEST['len'])) {
      $l = intval($_REQUEST['len']);
      if ($l >= 4 && $l <= 8) { $len = $l; }
    }
    $min = (int) pow(10, max(1, $len - 1));
    $max = (int) pow(10, $len) - 1;
    try {
      $code = (string) random_int($min, $max);
    } catch (Exception $e) {
      $code = (string) mt_rand($min, $max);
    }
    $ttl = 120; // seconds
    $_SESSION['captcha_code'] = $code;
    $_SESSION['captcha_expires'] = time() + $ttl;
    return json_encode(['success' => 1, 'captcha' => $code, 'expires_in' => $ttl, 'length' => $len]);
  }

  /**
   * AUTHENTICATE USER LOGIN
   * Validates credentials with captcha verification
   * Handles account blocking and session management
   */
  function login($conn, $json){
    $data = json_decode($json, true);
    $username = isset($data['username']) ? trim($data['username']) : '';
    $password = isset($data['password']) ? $data['password'] : '';
    $captchaInput = isset($data['captcha']) ? trim($data['captcha']) : '';
    
    if (!$username || !$password) {
      return json_encode(['success' => 0, 'message' => 'Missing credentials']);
    }

    // CAPTCHA validation (session-based)
    if ($captchaInput === '') {
      return json_encode(['success' => 0, 'message' => 'Captcha is required', 'captcha_required' => 1]);
    }
    if (!isset($_SESSION['captcha_code']) || !isset($_SESSION['captcha_expires'])) {
      return json_encode(['success' => 0, 'message' => 'Captcha is required', 'captcha_required' => 1]);
    }
    if (time() > intval($_SESSION['captcha_expires'])) {
      unset($_SESSION['captcha_code']); unset($_SESSION['captcha_expires']);
      return json_encode(['success' => 0, 'message' => 'Captcha expired. Please try again.', 'captcha_expired' => 1]);
    }
    if (strval($captchaInput) !== strval($_SESSION['captcha_code'])) {
      return json_encode(['success' => 0, 'message' => 'Invalid captcha', 'captcha_invalid' => 1]);
    }
    // One-time use captcha on success path
    unset($_SESSION['captcha_code']); unset($_SESSION['captcha_expires']);
    
    $stmt = $conn->prepare('SELECT user_id, username, password, role, employee_id FROM tblusers WHERE username = :u LIMIT 1');
    $stmt->bindParam(':u', $username);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    // Early block: If account is linked to an employee and is inactive, block login regardless of password correctness
    if ($user) {
      $eid = isset($user['employee_id']) ? intval($user['employee_id']) : 0;
      if ($eid > 0) {
        $emp = $conn->prepare('SELECT status FROM tblemployees WHERE employee_id = :id LIMIT 1');
        $emp->bindParam(':id', $eid, PDO::PARAM_INT);
        $emp->execute();
        $e = $emp->fetch(PDO::FETCH_ASSOC);
        if ($e && strtolower(trim($e['status'] ?? '')) === 'inactive'){
          return json_encode(['success' => 0, 'message' => 'This account has been inactive.']);
        }
      }
    }

    // Check account block (permanent) before anything else
    if ($user) {
      try {
        $uid = intval($user['user_id']);
        $blk = $conn->prepare("SELECT a.created_at AS blocked_at FROM tblaudit_logs a
                                LEFT JOIN (
                                  SELECT user_id, MAX(created_at) AS unblocked_at
                                  FROM tblaudit_logs
                                  WHERE action = 'account_unblocked'
                                  GROUP BY user_id
                                ) u ON u.user_id = a.user_id
                                WHERE a.user_id = :uid AND a.action = 'account_blocked'
                                ORDER BY a.created_at DESC LIMIT 1");
        $blk->bindParam(':uid', $uid, PDO::PARAM_INT);
        $blk->execute();
        $lastBlock = $blk->fetch(PDO::FETCH_ASSOC);
        if ($lastBlock) {
          // Check if there was an unblock after this block
          $ub = $conn->prepare("SELECT MAX(created_at) AS unblocked_at FROM tblaudit_logs WHERE user_id = :uid AND action = 'account_unblocked'");
          $ub->bindParam(':uid', $uid, PDO::PARAM_INT);
          $ub->execute();
          $unb = $ub->fetch(PDO::FETCH_ASSOC);
          $unblockedAt = $unb && $unb['unblocked_at'] ? strtotime($unb['unblocked_at']) : 0;
          $blockedAt = strtotime($lastBlock['blocked_at']);
          if ($blockedAt && $blockedAt >= $unblockedAt) {
            return json_encode(['success' => 0, 'message' => 'This account is blocked. Please contact an administrator.', 'blocked' => true]);
          }
        }
      } catch (Exception $e) { /* ignore */ }
    }

    // Check account lockout before verifying password
    $threshold = intval(getSystemSetting($conn, 'account_lockout_threshold', 5));
    $lockMinutes = intval(getSystemSetting($conn, 'account_lockout_duration_minutes', 15));
    $escEnabled = intval(getSystemSetting($conn, 'account_lockout_escalation_enabled', 0)) === 1;
    $escFirst = intval(getSystemSetting($conn, 'account_lockout_first_minutes', 5));
    $escSecond = intval(getSystemSetting($conn, 'account_lockout_second_minutes', 15));
    $escThird = intval(getSystemSetting($conn, 'account_lockout_third_minutes', 30));
    // Attempts escalation settings
    $attEscEnabled = intval(getSystemSetting($conn, 'account_lockout_escalation_attempts_enabled', 0)) === 1;
    $attFirst = intval(getSystemSetting($conn, 'account_lockout_first_attempts', 5));
    $attSecond = intval(getSystemSetting($conn, 'account_lockout_second_attempts', 4));
    $attThird = intval(getSystemSetting($conn, 'account_lockout_third_attempts', 3));
    if ($user && ($threshold > 0 || $attEscEnabled)) {
      try {
        $lockStmt = $conn->prepare("SELECT details, created_at FROM tblaudit_logs WHERE user_id = :uid AND action = 'login_lockout' ORDER BY created_at DESC LIMIT 1");
        $uid = intval($user['user_id']);
        $lockStmt->bindParam(':uid', $uid, PDO::PARAM_INT);
        $lockStmt->execute();
        $lock = $lockStmt->fetch(PDO::FETCH_ASSOC);
        if ($lock) {
          $until = null;
          $details = $lock['details'] ?? '';
          // details may be JSON or text
          $d = json_decode($details, true);
          if (is_array($d) && isset($d['lockout_until'])) { $until = $d['lockout_until']; }
          if (!$until && preg_match('/lockout_until\s*[:=]\s*([0-9\-:\s]+)/i', $details, $m)) { $until = trim($m[1]); }
          if ($until && strtotime($until) > time()) {
            $remaining = max(0, strtotime($until) - time());
            return json_encode(['success' => 0, 'message' => 'Account is locked. Try again later.', 'lockout' => true, 'lockout_until' => $until, 'remaining_seconds' => $remaining]);
          }
        }
      } catch (Exception $e) { /* ignore */ }
    }

    if ($user && password_verify($password, $user['password'])){
      // Compute employee link for session/enrichment
      $eid = isset($user['employee_id']) ? intval($user['employee_id']) : 0;

      $_SESSION['user_id'] = $user['user_id'];
      $_SESSION['username'] = $user['username'];
      $_SESSION['role'] = $user['role'];
      $_SESSION['employee_id'] = $eid > 0 ? $eid : null;
      $_SESSION['last_activity'] = time();

      // Log the login activity
      try {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $stmt = $conn->prepare("INSERT INTO tblaudit_logs (user_id, action, details, ip_address) VALUES (:user_id, 'login', :details, :ip)");
        $details = "User {$user['username']} logged in successfully";
        $stmt->bindParam(':user_id', $user['user_id'], PDO::PARAM_INT);
        $stmt->bindParam(':details', $details);
        $stmt->bindParam(':ip', $ip);
        $stmt->execute();
      } catch (Exception $e) {
        // Ignore logging errors
      }

      $respUser = [
        'username' => $user['username'],
        'role' => $user['role'],
        'employee_id' => $_SESSION['employee_id']
      ];
      // Enrich with employee personal details if linked
      if (!empty($_SESSION['employee_id'])) {
        $emp = $conn->prepare('SELECT employee_id, first_name, last_name, email, phone, department, position FROM tblemployees WHERE employee_id = :id LIMIT 1');
        $emp->bindParam(':id', $eid, PDO::PARAM_INT);
        $emp->execute();
        $e = $emp->fetch(PDO::FETCH_ASSOC);
        if ($e){
          $respUser = array_merge($respUser, [
            'first_name' => $e['first_name'],
            'last_name' => $e['last_name'],
            'email' => $e['email'],
            'phone' => $e['phone'],
            'department' => $e['department'],
            'position' => $e['position']
          ]);
        }
      }
      return json_encode(['success' => 1, 'user' => $respUser]);
    }

    // Handle failed login attempt and enforce lockout policy
    try {
      $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
      $uid = ($user && isset($user['user_id'])) ? intval($user['user_id']) : null;
      // Log failed attempt
      $stmt = $conn->prepare("INSERT INTO tblaudit_logs (user_id, action, details, ip_address) VALUES (:uid, 'login_failed', :details, :ip)");
      $det = 'Failed login' . ($user ? ' for user ' . $user['username'] : ' for unknown user ' . $username);
      if ($uid) { $stmt->bindParam(':uid', $uid, PDO::PARAM_INT); } else { $stmt->bindValue(':uid', null, PDO::PARAM_NULL); }
      $stmt->bindParam(':details', $det);
      $stmt->bindParam(':ip', $ip);
      $stmt->execute();

      // Enforce lockout if configured and user exists
      if ($user && ($threshold > 0 || $attEscEnabled)) {
        // Count failed attempts since last successful login
        $lastLoginAt = '1970-01-01 00:00:00';
        try {
          $ls = $conn->prepare("SELECT created_at FROM tblaudit_logs WHERE user_id = :uid AND action = 'login' ORDER BY created_at DESC LIMIT 1");
          $ls->bindParam(':uid', $uid, PDO::PARAM_INT);
          $ls->execute();
          $lr = $ls->fetch(PDO::FETCH_ASSOC);
          if ($lr && !empty($lr['created_at'])) { $lastLoginAt = $lr['created_at']; }
        } catch (Exception $e) { /* ignore */ }

        // Determine reference point for attempts (since last lockout or last login)
        $lastLockoutAt = null;
        try {
          $lkLatest = $conn->prepare("SELECT created_at FROM tblaudit_logs WHERE user_id = :uid AND action = 'login_lockout' ORDER BY created_at DESC LIMIT 1");
          $lkLatest->bindParam(':uid', $uid, PDO::PARAM_INT);
          $lkLatest->execute();
          $lr0 = $lkLatest->fetch(PDO::FETCH_ASSOC);
          if ($lr0 && !empty($lr0['created_at'])) { $lastLockoutAt = $lr0['created_at']; }
        } catch (Exception $e) {}
        $refAt = $lastLoginAt;
        if ($lastLockoutAt && strtotime($lastLockoutAt) > strtotime($lastLoginAt)) { $refAt = $lastLockoutAt; }

        // Count failed attempts from reference point
        $cntStmt = $conn->prepare("SELECT COUNT(*) AS c FROM tblaudit_logs WHERE user_id = :uid AND action = 'login_failed' AND created_at > :since");
        $cntStmt->bindParam(':uid', $uid, PDO::PARAM_INT);
        $cntStmt->bindParam(':since', $refAt);
        $cntStmt->execute();
        $row = $cntStmt->fetch(PDO::FETCH_ASSOC);
        $failedSinceRef = intval($row ? $row['c'] : 0);

        // Determine dynamic attempts threshold for this stage
        $dynamicThreshold = max(1, $threshold);
        if ($attEscEnabled) {
          $lkCountForStage = 0;
          try {
            $lkCntQ = $conn->prepare("SELECT COUNT(*) AS c FROM tblaudit_logs WHERE user_id = :uid AND action = 'login_lockout' AND created_at > :since");
            $lkCntQ->bindParam(':uid', $uid, PDO::PARAM_INT);
            $lkCntQ->bindParam(':since', $lastLoginAt);
            $lkCntQ->execute();
            $lkRow = $lkCntQ->fetch(PDO::FETCH_ASSOC);
            $lkCountForStage = intval($lkRow ? $lkRow['c'] : 0);
          } catch (Exception $e) {}
          if ($lkCountForStage <= 0)      { $dynamicThreshold = max(1, $attFirst); }
          else if ($lkCountForStage === 1) { $dynamicThreshold = max(1, $attSecond); }
          else                              { $dynamicThreshold = max(1, $attThird); }
        }

        if ($failedSinceRef >= max(1, $dynamicThreshold)) {
          // Determine lockout duration (escalation if enabled) or permanent block at 4th
          $durationMinutes = max(1, $lockMinutes);
          $lkCount = 0;
          if ($escEnabled) {
            // Count lockouts since last successful login
            try {
              $lkStmt = $conn->prepare("SELECT COUNT(*) AS c FROM tblaudit_logs WHERE user_id = :uid AND action = 'login_lockout' AND created_at > :since");
              $lkStmt->bindParam(':uid', $uid, PDO::PARAM_INT);
              $lkStmt->bindParam(':since', $lastLoginAt);
              $lkStmt->execute();
              $lrk = $lkStmt->fetch(PDO::FETCH_ASSOC);
              $lkCount = intval($lrk ? $lrk['c'] : 0);
            } catch (Exception $e) {}
            // On 4th lockout (lkCount >= 3), permanently block
            if ($lkCount >= 3) {
              try {
                $details = json_encode([
                  'username' => $user['username'],
                  'reason' => 'Exceeded maximum lockouts (4th lockout)',
                  'failed_attempts_count' => $failedSinceRef,
                  'ip' => $ip
                ]);
                $blk = $conn->prepare("INSERT INTO tblaudit_logs (user_id, action, details, ip_address) VALUES (:uid, 'account_blocked', :details, :ip)");
                $blk->bindParam(':uid', $uid, PDO::PARAM_INT);
                $blk->bindParam(':details', $details);
                $blk->bindParam(':ip', $ip);
                $blk->execute();
              } catch (Exception $e) { /* ignore */ }

              // Notify admins about account block
              try {
                // Get employee name if available
                $empName = '';
                try {
                  $empStmt = $conn->prepare('SELECT first_name, last_name FROM tblemployees e JOIN tblusers u ON e.employee_id = u.employee_id WHERE u.user_id = :user_id LIMIT 1');
                  $empStmt->bindParam(':user_id', $user['user_id'], PDO::PARAM_INT);
                  $empStmt->execute();
                  $empInfo = $empStmt->fetch(PDO::FETCH_ASSOC);
                  if ($empInfo) {
                    $empName = trim($empInfo['first_name'] . ' ' . $empInfo['last_name']);
                  }
                } catch (Exception $e) { /* ignore errors */ }
                
                $uname = $user['username'];
                $displayName = $empName ? $empName . ' (' . $uname . ')' : $uname;
                $msg = 'Account blocked for user ' . $displayName . ' after repeated failed logins';
                $sentBlocked = notifyAdmins($conn, 'account_blocked', $msg, null);
                // Fallback: record event so admin dashboard shows it if no admin employee mapping exists
                $eid = isset($user['employee_id']) ? (int)$user['employee_id'] : 0;
                if ($sentBlocked <= 0 && $eid > 0) {
                  try {
                    $ins = $conn->prepare('INSERT INTO tblnotifications (employee_id, message, type, actor_user_id) VALUES (:eid, :msg, :type, :actor)');
                    $ins->bindValue(':eid', $eid, PDO::PARAM_INT);
                    $ins->bindValue(':msg', $msg);
                    $ins->bindValue(':type', 'account_blocked');
                    $ins->bindValue(':actor', null, PDO::PARAM_NULL);
                    $ins->execute();
                  } catch (Exception $e3) { /* ignore */ }
                }
              } catch (Exception $e2) { /* ignore notif errors */ }
              
              return json_encode([
                'success' => 0,
                'message' => 'Your account has been blocked due to repeated failed logins. Contact an administrator to unblock.',
                'blocked' => true
              ]);
            }
            if ($lkCount <= 0)      $durationMinutes = max(1, $escFirst);
            else if ($lkCount === 1) $durationMinutes = max(1, $escSecond);
            else                      $durationMinutes = max(1, $escThird);
          }
          // Initiate lockout
          $untilTs = time() + $durationMinutes * 60;
          $until = date('Y-m-d H:i:s', $untilTs);
          $lockoutLevel = 'standard';
          if ($escEnabled) {
            if ($lkCount <= 0) $lockoutLevel = 'first';
            else if ($lkCount === 1) $lockoutLevel = 'second';
            else $lockoutLevel = 'third+';
          }
          $lockDetails = json_encode([
            'username' => $user['username'],
            'lockout_until' => $until,
            'threshold' => $threshold,
            'duration_minutes' => $durationMinutes,
            'ip' => $ip,
            'escalation' => $escEnabled ? ['first'=>$escFirst,'second'=>$escSecond,'third'=>$escThird] : null,
            'lockout_level' => $lockoutLevel
          ]);
          try {
            $lk = $conn->prepare("INSERT INTO tblaudit_logs (user_id, action, details, ip_address) VALUES (:uid, 'login_lockout', :details, :ip)");
            $lk->bindParam(':uid', $uid, PDO::PARAM_INT);
            $lk->bindParam(':details', $lockDetails);
            $lk->bindParam(':ip', $ip);
            $lk->execute();
          } catch (Exception $e) { /* ignore */ }
          // Notify admins about account lockout (temporary)
          try {
            // Build display name
            $empName = '';
            try {
              $empStmt = $conn->prepare('SELECT first_name, last_name FROM tblemployees e JOIN tblusers u ON e.employee_id = u.employee_id WHERE u.user_id = :user_id LIMIT 1');
              $empStmt->bindParam(':user_id', $user['user_id'], PDO::PARAM_INT);
              $empStmt->execute();
              $empInfo = $empStmt->fetch(PDO::FETCH_ASSOC);
              if ($empInfo) { $empName = trim($empInfo['first_name'] . ' ' . $empInfo['last_name']); }
            } catch (Exception $e2) { /* ignore */ }
            $uname = $user['username'];
            $displayName = $empName ? $empName . ' (' . $uname . ')' : $uname;
            $msg = 'Account lockout for user ' . $displayName . ' until ' . $until . ' (' . $durationMinutes . ' minutes)';
            $sentLock = notifyAdmins($conn, 'account_lockout', $msg, null);
            $eid = isset($user['employee_id']) ? (int)$user['employee_id'] : 0;
            if ($sentLock <= 0 && $eid > 0) {
              try {
                $ins = $conn->prepare('INSERT INTO tblnotifications (employee_id, message, type, actor_user_id) VALUES (:eid, :msg, :type, :actor)');
                $ins->bindValue(':eid', $eid, PDO::PARAM_INT);
                $ins->bindValue(':msg', $msg);
                $ins->bindValue(':type', 'account_lockout');
                $ins->bindValue(':actor', null, PDO::PARAM_NULL);
                $ins->execute();
              } catch (Exception $e3) { /* ignore */ }
            }
          } catch (Exception $e) { /* ignore notify errors */ }
          $remaining = max(0, $untilTs - time());
          return json_encode([
            'success' => 0,
            'message' => 'Account locked due to too many failed attempts. Try again later.',
            'lockout' => true,
            'lockout_until' => $until,
            'remaining_seconds' => $remaining,
            'duration_minutes' => $durationMinutes,
            'lockout_level' => $lockoutLevel,
            'escalation_enabled' => $escEnabled ? 1 : 0,
            'failed_attempts_count' => $failedSinceRef,
            'threshold' => $dynamicThreshold
          ]);
        }
        // Not yet locked: include attempts remaining
        $remainingAttempts = max(0, $dynamicThreshold - $failedSinceRef);
        $extra = [];
        if ($remainingAttempts === 1) {
          // compute next lockout duration
          $nextMins = max(1, $lockMinutes);
          if ($escEnabled) {
            $lkCount = 0;
            try {
              $lkStmt = $conn->prepare("SELECT COUNT(*) AS c FROM tblaudit_logs WHERE user_id = :uid AND action = 'login_lockout' AND created_at > :since");
              $lkStmt->bindParam(':uid', $uid, PDO::PARAM_INT);
              $lkStmt->bindParam(':since', $lastLoginAt);
              $lkStmt->execute();
              $lrk = $lkStmt->fetch(PDO::FETCH_ASSOC);
              $lkCount = intval($lrk ? $lrk['c'] : 0);
            } catch (Exception $e) {}
            if ($lkCount <= 0)      $nextMins = max(1, $escFirst);
            else if ($lkCount === 1) $nextMins = max(1, $escSecond);
            else                      $nextMins = max(1, $escThird);
          }
          $extra = ['next_lockout_minutes' => $nextMins];
        }
        return json_encode(array_merge([
          'success' => 0,
          'message' => 'Invalid username or password',
          'attempts_remaining' => $remainingAttempts,
          'threshold' => $dynamicThreshold,
          'failed_attempts_count' => $failedSinceRef
        ], $extra));
      }
    } catch (Exception $e) { /* ignore */ }

    return json_encode(['success' => 0, 'message' => 'Invalid username or password']);
  }

  function me(){
    if (isset($_SESSION['user_id'])){
      // Enforce session timeout and refresh activity timestamp
      include 'connection-pdo.php';
      $info = checkAndRefreshSession($conn);
      if ($info['expired']) {
        return json_encode(['authenticated' => false, 'session_expired' => true, 'timeout_minutes' => $info['timeout_minutes']]);
      }
      $user = [
        'username' => isset($_SESSION['username']) ? $_SESSION['username'] : null,
        'role' => isset($_SESSION['role']) ? $_SESSION['role'] : null,
        'employee_id' => isset($_SESSION['employee_id']) ? $_SESSION['employee_id'] : null,
      ];
      // Enrich with employee personal details if linked
      if (!empty($user['employee_id'])){
        $eid = intval($user['employee_id']);
        try {
          $emp = $conn->prepare('SELECT employee_id, first_name, last_name, email, phone, department, position FROM tblemployees WHERE employee_id = :id LIMIT 1');
          $emp->bindParam(':id', $eid, PDO::PARAM_INT);
          $emp->execute();
          $e = $emp->fetch(PDO::FETCH_ASSOC);
          if ($e){
            $user = array_merge($user, [
              'first_name' => $e['first_name'],
              'last_name' => $e['last_name'],
              'email' => $e['email'],
              'phone' => $e['phone'],
              'department' => $e['department'],
              'position' => $e['position']
            ]);
          }
        } catch (Exception $e) {
          // ignore enrichment errors
        }
      }
      return json_encode(['authenticated' => true, 'user' => $user]);
    }
    return json_encode(['authenticated' => false]);
  }

  function logout(){
    // Log the logout activity
    try {
      include 'connection-pdo.php';
      $userId = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null;
      $username = isset($_SESSION['username']) ? $_SESSION['username'] : 'Unknown';
      $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
      $stmt = $conn->prepare("INSERT INTO tblaudit_logs (user_id, action, details, ip_address) VALUES (:user_id, 'logout', :details, :ip)");
      $details = "User {$username} logged out";
      $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
      $stmt->bindParam(':details', $details);
      $stmt->bindParam(':ip', $ip);
      $stmt->execute();
    } catch (Exception $e) {
      // Ignore logging errors
    }

    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
      $params = session_get_cookie_params();
      setcookie(session_name(), '', time() - 42000,
        $params['path'], $params['domain'],
        $params['secure'], $params['httponly']
      );
    }
    session_destroy();
    return json_encode(['success' => 1]);
  }

  function updateProfile($conn, $json){
    if (!isset($_SESSION['user_id'])){
      return json_encode(['success' => 0, 'message' => 'Not authenticated']);
    }
    $data = json_decode($json, true);
    if (!$data) $data = [];
    $userId = intval($_SESSION['user_id']);
    $newUsername = isset($data['username']) ? trim($data['username']) : '';
    $newPassword = isset($data['password']) ? trim($data['password']) : '';
    $response = ['success' => 1];
    if ($newUsername !== ''){
      // ensure no conflict with another user
      $conf = $conn->prepare('SELECT user_id FROM tblusers WHERE username = :u AND user_id <> :id LIMIT 1');
      $conf->bindParam(':u', $newUsername);
      $conf->bindParam(':id', $userId, PDO::PARAM_INT);
      $conf->execute();
      $row = $conf->fetch(PDO::FETCH_ASSOC);
      if ($row){
        $response['success'] = 0;
        $response['message'] = 'Username already taken';
        return json_encode($response);
      }
      $upd = $conn->prepare('UPDATE tblusers SET username = :u WHERE user_id = :id');
      $upd->bindParam(':u', $newUsername);
      $upd->bindParam(':id', $userId, PDO::PARAM_INT);
      $upd->execute();
      $_SESSION['username'] = $newUsername;
    }
    if ($newPassword !== ''){
      $hash = password_hash($newPassword, PASSWORD_DEFAULT);
      $upd = $conn->prepare('UPDATE tblusers SET password = :p WHERE user_id = :id');
      $upd->bindParam(':p', $hash);
      $upd->bindParam(':id', $userId, PDO::PARAM_INT);
      $upd->execute();

      // Notify admins about password change
      try {
        // Build display name for the actor
        $uinfo = null;
        try {
          $uq = $conn->prepare('SELECT u.username, u.employee_id, e.first_name, e.last_name FROM tblusers u LEFT JOIN tblemployees e ON e.employee_id = u.employee_id WHERE u.user_id = :id LIMIT 1');
          $uq->bindParam(':id', $userId, PDO::PARAM_INT);
          $uq->execute();
          $uinfo = $uq->fetch(PDO::FETCH_ASSOC);
        } catch (Exception $e2) { /* ignore */ }
        $uname = $uinfo && !empty($uinfo['username']) ? $uinfo['username'] : (isset($_SESSION['username']) ? $_SESSION['username'] : ('User #' . $userId));
        $empName = ($uinfo && (!empty($uinfo['first_name']) || !empty($uinfo['last_name']))) ? trim($uinfo['first_name'] . ' ' . $uinfo['last_name']) : '';
        $displayName = $empName ? ($empName . ' (' . $uname . ')') : $uname;
        $msg = 'Password changed by ' . $displayName;
        $sent = notifyAdmins($conn, 'password_changed', $msg, $userId);
        // Fallback: record the event so admin dashboard can see it even if no admin employee mapping exists
        $eid = ($uinfo && !empty($uinfo['employee_id'])) ? (int)$uinfo['employee_id'] : 0;
        if ($sent <= 0 && $eid > 0) {
          try {
            $ins = $conn->prepare('INSERT INTO tblnotifications (employee_id, message, type, actor_user_id) VALUES (:eid, :msg, :type, :actor)');
            $ins->bindValue(':eid', $eid, PDO::PARAM_INT);
            $ins->bindValue(':msg', $msg);
            $ins->bindValue(':type', 'password_changed');
            $ins->bindValue(':actor', $userId, PDO::PARAM_INT);
            $ins->execute();
          } catch (Exception $e3) { /* ignore */ }
        }
      } catch (Exception $e) { /* ignore notify errors */ }
    }
    return json_encode($response);
  }

  function forgotPassword($conn, $json) {
    $data = json_decode($json, true);
    $username = isset($data['username']) ? trim($data['username']) : '';
    
    if (!$username) {
      return json_encode(['success' => 0, 'message' => 'Username or email is required']);
    }
    
    // Simple rate limiting - check if too many requests from same IP
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $rateLimitKey = "forgot_password_limit_{$ip}";
    
    if (isset($_SESSION[$rateLimitKey]) && $_SESSION[$rateLimitKey]['count'] >= MAX_RESET_ATTEMPTS) {
      $timeDiff = time() - $_SESSION[$rateLimitKey]['time'];
      if ($timeDiff < (RATE_LIMIT_HOURS * 3600)) { // Convert hours to seconds
        return json_encode(['success' => 0, 'message' => 'Too many requests. Please try again in ' . RATE_LIMIT_HOURS . ' hour(s).']);
      } else {
        // Reset counter after rate limit period
        unset($_SESSION[$rateLimitKey]);
      }
    }
    
    try {
      // Check if user exists and get email and employee status
      $stmt = $conn->prepare('SELECT u.user_id, u.username, e.email, e.status AS emp_status FROM tblusers u LEFT JOIN tblemployees e ON u.employee_id = e.employee_id WHERE u.username = :u LIMIT 1');
      $stmt->bindParam(':u', $username);
      $stmt->execute();
      $user = $stmt->fetch(PDO::FETCH_ASSOC);
      
      if (!$user) {
        // For security, don't reveal if user exists or not
        // Still apply rate limiting even for non-existent users
        if (!isset($_SESSION[$rateLimitKey])) {
          $_SESSION[$rateLimitKey] = ['count' => 1, 'time' => time()];
        } else {
          $_SESSION[$rateLimitKey]['count']++;
        }
        return json_encode(['success' => 1, 'message' => 'If the username exists, a reset code will be sent to your email']);
      }
      // Block reset for inactive employee accounts
      if (isset($user['emp_status']) && strtolower(trim($user['emp_status'])) === 'inactive') {
        return json_encode(['success' => 0, 'message' => 'Cannot process password reset for inactive account.']);
      }
      
      // Generate 6-digit code
      $code = sprintf('%06d', mt_rand(0, 999999));
      $expires = date('Y-m-d H:i:s', strtotime('+' . CODE_EXPIRY_MINUTES . ' minutes'));
      
      // Store reset code in database
      $updateStmt = $conn->prepare('UPDATE tblusers SET reset_code = :code, reset_code_expires = :expires WHERE user_id = :id');
      $updateStmt->bindParam(':code', $code);
      $updateStmt->bindParam(':expires', $expires);
      $updateStmt->bindParam(':id', $user['user_id'], PDO::PARAM_INT);
      $updateStmt->execute();
      
      // Update rate limiting
      if (!isset($_SESSION[$rateLimitKey])) {
        $_SESSION[$rateLimitKey] = ['count' => 1, 'time' => time()];
      } else {
        $_SESSION[$rateLimitKey]['count']++;
      }
      
      // Send email with PHPMailer
      $emailSent = sendResetCodeEmail($user['email'] ?? $user['username'], $code, $user['username']);
      
      if ($emailSent) {
        return json_encode(['success' => 1, 'message' => 'A 6-digit reset code has been sent to your email. Please check your inbox.']);
      } else {
        return json_encode(['success' => 0, 'message' => 'Failed to send email. Please try again later.']);
      }
      
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'An error occurred while processing your request']);
    }
  }

  function resetPassword($conn, $json) {
    $data = json_decode($json, true);
    $code = isset($data['code']) ? trim($data['code']) : '';
    $newPassword = isset($data['newPassword']) ? trim($data['newPassword']) : '';
    
    if (!$code || strlen($code) !== 6) {
      return json_encode(['success' => 0, 'message' => 'Valid 6-digit code is required']);
    }
    
    if (strlen($newPassword) < 6) {
      return json_encode(['success' => 0, 'message' => 'Password must be at least 6 characters long']);
    }
    
    try {
      // Debug: Log the received code
      error_log("Reset password attempt - Code received: " . $code);
      
      // Find user with valid reset code
      $stmt = $conn->prepare('SELECT user_id, reset_code, reset_code_expires FROM tblusers WHERE reset_code = :code LIMIT 1');
      $stmt->bindParam(':code', $code);
      $stmt->execute();
      $user = $stmt->fetch(PDO::FETCH_ASSOC);
      
      // Debug: Log what we found
      if ($user) {
        error_log("User found - Stored code: " . $user['reset_code'] . ", Expires: " . $user['reset_code_expires']);
      } else {
        error_log("No user found with code: " . $code);
      }
      
      if (!$user) {
        return json_encode(['success' => 0, 'message' => 'Invalid reset code']);
      }
      
      // Check if code is expired
      if ($user['reset_code_expires'] < date('Y-m-d H:i:s')) {
        error_log("Code expired - Current time: " . date('Y-m-d H:i:s') . ", Expires: " . $user['reset_code_expires']);
        return json_encode(['success' => 0, 'message' => 'Reset code has expired. Please request a new one.']);
      }
      
      // Hash new password and update user
      $hash = password_hash($newPassword, PASSWORD_DEFAULT);
      $updateStmt = $conn->prepare('UPDATE tblusers SET password = :password, reset_code = NULL, reset_code_expires = NULL WHERE user_id = :id');
      $updateStmt->bindParam(':password', $hash);
      $updateStmt->bindParam(':id', $user['user_id'], PDO::PARAM_INT);
      $updateStmt->execute();

      // Notify admins of successful password reset (actor unknown here)
      try {
        $uinfo = null;
        try {
          $uq = $conn->prepare('SELECT username, employee_id FROM tblusers WHERE user_id = :id LIMIT 1');
          $uq->bindParam(':id', $user['user_id'], PDO::PARAM_INT);
          $uq->execute();
          $uinfo = $uq->fetch(PDO::FETCH_ASSOC);
        } catch (Exception $e2) { /* ignore */ }
        
        // Get employee name if available
        $empName = '';
        if ($uinfo && !empty($uinfo['employee_id'])) {
          try {
            $empStmt = $conn->prepare('SELECT first_name, last_name FROM tblemployees WHERE employee_id = :emp_id LIMIT 1');
            $empStmt->bindParam(':emp_id', $uinfo['employee_id'], PDO::PARAM_INT);
            $empStmt->execute();
            $empInfo = $empStmt->fetch(PDO::FETCH_ASSOC);
            if ($empInfo) {
              $empName = trim($empInfo['first_name'] . ' ' . $empInfo['last_name']);
            }
          } catch (Exception $e3) { /* ignore errors */ }
        }
        
        $uname = $uinfo && !empty($uinfo['username']) ? $uinfo['username'] : ('User #' . $user['user_id']);
        $displayName = $empName ? $empName . ' (' . $uname . ')' : $uname;
        $msg = 'Password reset completed by ' . $displayName . ' via reset code';
        $sentReset = notifyAdmins($conn, 'password_reset', $msg, null);
        // Fallback: record event for admin dashboard visibility if no admin mapping exists
        $eid = ($uinfo && !empty($uinfo['employee_id'])) ? (int)$uinfo['employee_id'] : 0;
        if ($sentReset <= 0 && $eid > 0) {
          try {
            $ins = $conn->prepare('INSERT INTO tblnotifications (employee_id, message, type, actor_user_id) VALUES (:eid, :msg, :type, :actor)');
            $ins->bindValue(':eid', $eid, PDO::PARAM_INT);
            $ins->bindValue(':msg', $msg);
            $ins->bindValue(':type', 'password_reset');
            $ins->bindValue(':actor', null, PDO::PARAM_NULL);
            $ins->execute();
          } catch (Exception $e4) { /* ignore */ }
        }
      } catch (Exception $e3) { /* ignore notif errors */ }
      
      error_log("Password reset successful for user ID: " . $user['user_id']);
      return json_encode(['success' => 1, 'message' => 'Password reset successfully']);
      
    } catch (Exception $e) {
      error_log("Error in resetPassword: " . $e->getMessage());
      return json_encode(['success' => 0, 'message' => 'An error occurred while resetting your password']);
    }
  }

  function sendResetCodeEmail($email, $code, $username) {
    try {
      // Include PHPMailer
      require_once '../phpmailer-master/src/Exception.php';
      require_once '../phpmailer-master/src/PHPMailer.php';
      require_once '../phpmailer-master/src/SMTP.php';
      
      $mail = new PHPMailer\PHPMailer\PHPMailer(true);
      
      // Set timeout to prevent hanging
      $mail->Timeout = 20; // 20 seconds timeout
      $mail->SMTPKeepAlive = false; // Don't keep connection alive
      
      // Server settings
      $mail->isSMTP();
      $mail->Host = SMTP_HOST;
      $mail->SMTPAuth = true;
      $mail->Username = SMTP_USERNAME;
      $mail->Password = SMTP_PASSWORD;
      $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
      $mail->Port = SMTP_PORT;
      
      // Debug mode (remove in production)
      $mail->SMTPDebug = 0; // Set to 2 for debugging
      
      // Recipients
      $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
      $mail->addAddress($email, $username);
      
      // Content
      $mail->isHTML(true);
      $mail->Subject = EMAIL_SUBJECT;
      $mail->Body = "
        <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
          <h2 style='color: #3b82f6;'>Password Reset Request</h2>
          <p>Hello <strong>{$username}</strong>,</p>
          <p>You have requested to reset your password. Use the following 6-digit code to complete the process:</p>
          <div style='background-color: #f3f4f6; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;'>
            <h1 style='color: #1f2937; font-size: 32px; letter-spacing: 8px; margin: 0;'>{$code}</h1>
          </div>
          <p><strong>Important:</strong></p>
          <ul>
            <li>This code will expire in " . CODE_EXPIRY_MINUTES . " minutes</li>
            <li>If you didn't request this, please ignore this email</li>
            <li>Never share this code with anyone</li>
          </ul>
          <p>Best regards,<br>" . SMTP_FROM_NAME . "</p>
        </div>
      ";
      $mail->AltBody = "
        Password Reset Request
        
        Hello {$username},
        
        You have requested to reset your password. Use the following 6-digit code to complete the process:
        
        {$code}
        
        Important:
        - This code will expire in " . CODE_EXPIRY_MINUTES . " minutes
        - If you didn't request this, please ignore this email
        - Never share this code with anyone
        
        Best regards,
        " . SMTP_FROM_NAME . "
      ";
      
      $mail->send();
      error_log("Email sent successfully to: " . $email);
      return true;
      
    } catch (Exception $e) {
      error_log("Email sending failed: " . $e->getMessage());
      return false;
    }
  }
?>


