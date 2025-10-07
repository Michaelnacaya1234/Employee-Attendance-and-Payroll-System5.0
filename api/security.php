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

require_once __DIR__ . '/connection-pdo.php';

$operation = '';
$json = '';
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $operation = isset($_GET['operation']) ? $_GET['operation'] : '';
} else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
  $json = isset($_POST['json']) ? $_POST['json'] : '';
}

switch ($operation) {
  case 'getSecuritySettings':
    echo getSecuritySettings($conn);
    break;
  case 'updateSecuritySettings':
    echo updateSecuritySettings($conn, $json);
    break;
  case 'listBlockedAccounts':
    echo listBlockedAccounts($conn);
    break;
  case 'unblockAccount':
    echo unblockAccount($conn, $json);
    break;
  default:
    echo json_encode(['success' => false, 'message' => 'Invalid operation']);
}

/**
 * SECURITY SETTINGS DEFAULT VALUES
 * Defines default security configuration for the system
 * Used when settings are not yet configured
 */
function securityDefaults() {
  return [
    'password_min_length' => '8',
    'password_require_uppercase' => '1',
    'password_require_number' => '1',
    'password_require_special' => '0',
    'password_expiry_days' => '0', // 0 = never
    'two_factor_enabled' => '0',
    'session_timeout_minutes' => '0',
    'remember_me_enabled' => '0',
    'account_lockout_threshold' => '5',
    'account_lockout_duration_minutes' => '15',
    // Escalation settings
    'account_lockout_escalation_enabled' => '1',
    'account_lockout_first_minutes' => '5',
    'account_lockout_second_minutes' => '15',
    'account_lockout_third_minutes' => '30',
    // Attempts escalation settings
    'account_lockout_escalation_attempts_enabled' => '0',
    'account_lockout_first_attempts' => '5',
    'account_lockout_second_attempts' => '4',
    'account_lockout_third_attempts' => '3'
  ];
}

/**
 * GET ALLOWED SECURITY SETTING KEYS
 * Returns list of valid security configuration keys
 * Used for validation and filtering
 */
function allowedSecurityKeys() {
  return array_keys(securityDefaults());
}

/**
 * RETRIEVE CURRENT SECURITY SETTINGS
 * Fetches security configuration from database
 * Returns defaults for missing settings
 */
function getSecuritySettings($conn) {
  try {
    $keys = allowedSecurityKeys();
    $in = implode(',', array_fill(0, count($keys), '?'));
    $stmt = $conn->prepare("SELECT setting_key, setting_value FROM tblsystem_settings WHERE setting_key IN ($in)");
    foreach ($keys as $i => $k) { $stmt->bindValue($i + 1, $k); }
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $defaults = securityDefaults();
    $out = $defaults;
    foreach ($rows as $row) { $out[$row['setting_key']] = $row['setting_value']; }
    return json_encode($out);
  } catch (Exception $e) {
    return json_encode(securityDefaults());
  }
}

/**
 * UPDATE SECURITY SETTINGS
 * Modifies security configuration with admin authorization
 * Logs changes to audit trail for compliance
 */
function updateSecuritySettings($conn, $json) {
  $data = json_decode($json, true);
  if (!is_array($data)) {
    return json_encode(['success' => false, 'message' => 'Invalid payload']);
  }
  // Only admin can update security settings
  $role = isset($_SESSION['role']) ? strtolower((string)$_SESSION['role']) : '';
  if ($role !== 'admin') {
    return json_encode(['success' => false, 'message' => 'Forbidden']);
  }
  $allowed = allowedSecurityKeys();
  $toSave = [];
  foreach ($allowed as $k) {
    if (array_key_exists($k, $data)) {
      $v = $data[$k];
      // Normalize values: booleans to 0/1, numbers to strings
      if (is_bool($v)) { $v = $v ? '1' : '0'; }
      if (is_numeric($v)) { $v = (string)$v; }
      if ($v === null) { $v = ''; }
      $toSave[$k] = $v;
    }
  }
  if (empty($toSave)) {
    return json_encode(['success' => false, 'message' => 'Nothing to update']);
  }
  try {
    $conn->beginTransaction();
    $sql = "INSERT INTO tblsystem_settings (setting_key, setting_value) VALUES (:k, :v)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
    $stmt = $conn->prepare($sql);
    foreach ($toSave as $k => $v) {
      $stmt->bindParam(':k', $k);
      $stmt->bindParam(':v', $v);
      $stmt->execute();
    }
    $conn->commit();

    // Log to audit logs if table/session available
    try {
      $uid = isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : null;
      $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
      $details = 'Updated security settings: ' . json_encode(array_keys($toSave));
      $log = $conn->prepare("INSERT INTO tblaudit_logs (user_id, action, details, ip_address) VALUES (:uid, 'update_security_settings', :details, :ip)");
      $log->bindParam(':uid', $uid, PDO::PARAM_INT);
      $log->bindParam(':details', $details);
      $log->bindParam(':ip', $ip);
      $log->execute();
    } catch (Exception $e) { /* ignore logging errors */ }

    return json_encode(['success' => true]);
  } catch (Exception $e) {
    if ($conn->inTransaction()) { $conn->rollBack(); }
    return json_encode(['success' => false, 'message' => 'Failed to update settings']);
  }
}

/**
 * LIST CURRENTLY BLOCKED ACCOUNTS
 * Retrieves accounts that are blocked and not yet unblocked
 * Includes user and employee details for management
 */
function listBlockedAccounts($conn) {
  try {
    // Latest block per user
    $sql = "
      SELECT u.user_id, u.username, u.role,
             e.first_name, e.last_name, e.email,
             ab.created_at AS blocked_at, ab.details AS block_details
      FROM tblusers u
      INNER JOIN tblaudit_logs ab
        ON ab.user_id = u.user_id AND ab.action = 'account_blocked'
      LEFT JOIN tblaudit_logs ub
        ON ub.user_id = u.user_id AND ub.action = 'account_unblocked' AND ub.created_at > ab.created_at
      LEFT JOIN tblemployees e ON e.employee_id = u.employee_id
      WHERE ub.user_id IS NULL
        AND ab.created_at = (
          SELECT MAX(ab2.created_at)
          FROM tblaudit_logs ab2
          WHERE ab2.user_id = u.user_id AND ab2.action = 'account_blocked'
        )
      ORDER BY ab.created_at DESC
    ";
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
      return json_encode([]);
    }
    $ok = false;
    try { $ok = $stmt->execute(); } catch (Exception $e) { $ok = false; }
    if (!$ok) {
      return json_encode([]);
    }
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $out = array_map(function($r){
      $full = trim(((string)($r['first_name'] ?? '') . ' ' . (string)($r['last_name'] ?? '')));
      return [
        'user_id' => (int)$r['user_id'],
        'username' => $r['username'],
        'role' => $r['role'],
        'full_name' => $full,
        'email' => $r['email'] ?? null,
        'blocked_at' => $r['blocked_at'],
        'block_details' => $r['block_details'] ?? null
      ];
    }, $rows);
    return json_encode($out);
  } catch (Exception $e) {
    return json_encode([]);
  }
}

/**
 * UNBLOCK USER ACCOUNT
 * Removes account block with audit logging
 * Allows user to login again after unblocking
 */
function unblockAccount($conn, $json) {
  $data = json_decode($json, true);
  $userId = isset($data['user_id']) ? intval($data['user_id']) : 0;
  if ($userId <= 0) return json_encode(['success' => false, 'message' => 'Invalid user']);
  try {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $details = 'Account unblocked by admin';
    $stmt = $conn->prepare("INSERT INTO tblaudit_logs (user_id, action, details, ip_address) VALUES (:uid, 'account_unblocked', :details, :ip)");
    $stmt->bindParam(':uid', $userId, PDO::PARAM_INT);
    $stmt->bindParam(':details', $details);
    $stmt->bindParam(':ip', $ip);
    $stmt->execute();
    return json_encode(['success' => true]);
  } catch (Exception $e) {
    return json_encode(['success' => false, 'message' => 'Failed to unblock']);
  }
}
