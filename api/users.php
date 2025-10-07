<?php
  header('Content-Type: application/json');
  header('Access-Control-Allow-Origin: *');
  if (session_status() === PHP_SESSION_NONE) { session_start(); }

  if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    exit(0);
  }

  include 'connection-pdo.php';

  $operation = '';
  $json = '';
  if ($_SERVER['REQUEST_METHOD'] == 'GET'){
    $operation = isset($_GET['operation']) ? $_GET['operation'] : '';
    $json = isset($_GET['json']) ? $_GET['json'] : '';
  } else if($_SERVER['REQUEST_METHOD'] == 'POST'){
    $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
    $json = isset($_POST['json']) ? $_POST['json'] : '';
  }

  // Simple auth guard: only admin and hr may manage users
  $role = isset($_SESSION['role']) ? strtolower((string)$_SESSION['role']) : null;
  $allowed = in_array($role, ['admin','hr'], true);
  if (!$allowed && !in_array($operation, ['me'], true)) {
    echo json_encode(['success' => 0, 'message' => 'Not authorized']);
    exit;
  }

  switch ($operation) {
    case 'listUsers':
      echo listUsers($conn);
      break;
    case 'getUser':
      echo getUser($conn);
      break;
    case 'createUser':
      echo createUser($conn, $json);
      break;
    case 'updateUser':
      echo updateUser($conn, $json);
      break;
    case 'deleteUser':
      echo deleteUser($conn, $json);
      break;
    case 'adminResetPassword':
      echo adminResetPassword($conn, $json);
      break;
    case 'setMappedEmployeeStatus':
      echo setMappedEmployeeStatus($conn, $json);
      break;
    default:
      echo json_encode([]);
  }

  /**
   * RETRIEVE ALL SYSTEM USERS
   * Fetches users with linked employee information
   * Supports search filtering by username and employee details
   */
  function listUsers($conn){
    try {
      $q = isset($_GET['q']) ? trim($_GET['q']) : '';
      $sql = "SELECT u.user_id, u.username, u.role, u.employee_id, u.created_at,
                     e.first_name, e.last_name, e.email, e.department, e.position, e.status AS emp_status
              FROM tblusers u
              LEFT JOIN tblemployees e ON e.employee_id = u.employee_id
              WHERE 1=1";
      $params = [];
      if ($q !== ''){
        $sql .= " AND (u.username LIKE :q OR e.first_name LIKE :q OR e.last_name LIKE :q OR e.email LIKE :q)";
        $params[':q'] = "%{$q}%";
      }
      $sql .= " ORDER BY u.created_at DESC";
      $stmt = $conn->prepare($sql);
      foreach ($params as $k=>$v){ $stmt->bindValue($k, $v); }
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
      return json_encode($rows ?: []);
    } catch (Exception $e) {
      return json_encode([]);
    }
  }

  /**
   * GET SINGLE USER BY ID
   * Retrieves detailed user information with employee data
   * Used for user profile management and editing
   */
  function getUser($conn){
    try {
      $id = isset($_GET['user_id']) ? intval($_GET['user_id']) : 0;
      if ($id <= 0) return json_encode(null);
      $stmt = $conn->prepare("SELECT u.user_id, u.username, u.role, u.employee_id, u.created_at,
                                     e.first_name, e.last_name, e.email, e.department, e.position, e.status AS emp_status
                              FROM tblusers u
                              LEFT JOIN tblemployees e ON e.employee_id = u.employee_id
                              WHERE u.user_id = :id LIMIT 1");
      $stmt->bindParam(':id', $id, PDO::PARAM_INT);
      $stmt->execute();
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      return json_encode($row ?: null);
    } catch (Exception $e) { return json_encode(null); }
  }

  /**
   * CREATE NEW SYSTEM USER
   * Creates user account with role assignment and password generation
   * Validates username uniqueness and role permissions
   */
  function createUser($conn, $json){
    $data = json_decode($json, true);
    $username = isset($data['username']) ? trim($data['username']) : '';
    $role = isset($data['role']) ? strtolower(trim($data['role'])) : '';
    $employee_id = isset($data['employee_id']) ? intval($data['employee_id']) : null;
    $password = isset($data['password']) ? (string)$data['password'] : '';
    if ($username === '' || !in_array($role, ['admin','hr','manager','employee'], true)){
      return json_encode(['success' => 0, 'message' => 'Invalid inputs']);
    }
    try {
      $conf = $conn->prepare('SELECT user_id FROM tblusers WHERE username = :u LIMIT 1');
      $conf->bindParam(':u', $username);
      $conf->execute();
      if ($conf->fetch(PDO::FETCH_ASSOC)){
        return json_encode(['success' => 0, 'message' => 'Username already exists']);
      }
      $plain = $password !== '' ? $password : generateRandomPassword(10);
      $hash = password_hash($plain, PASSWORD_DEFAULT);
      $ins = $conn->prepare('INSERT INTO tblusers(username, password, role, employee_id) VALUES(:u, :p, :r, :eid)');
      $ins->bindParam(':u', $username);
      $ins->bindParam(':p', $hash);
      $ins->bindParam(':r', $role);
      if ($employee_id){ $ins->bindParam(':eid', $employee_id, PDO::PARAM_INT); }
      else { $null = null; $ins->bindParam(':eid', $null, PDO::PARAM_NULL); }
      $ins->execute();
      $id = (int)$conn->lastInsertId();
      return json_encode(['success' => 1, 'user_id' => $id, 'generated_password' => ($password === '' ? $plain : null)]);
    } catch (Exception $e){
      return json_encode(['success' => 0, 'message' => 'Failed to create user']);
    }
  }

  /**
   * UPDATE EXISTING USER ACCOUNT
   * Modifies user details including role and employee mapping
   * Maintains username uniqueness and data integrity
   */
  function updateUser($conn, $json){
    $data = json_decode($json, true);
    $id = isset($data['user_id']) ? intval($data['user_id']) : 0;
    if ($id <= 0) return json_encode(['success' => 0]);
    $username = isset($data['username']) ? trim($data['username']) : null;
    $role = isset($data['role']) ? strtolower(trim($data['role'])) : null;
    $employee_id = array_key_exists('employee_id', $data) ? (is_null($data['employee_id']) ? null : intval($data['employee_id'])) : null;

    try {
      // Enforce unique username if updating
      if ($username !== null && $username !== ''){
        $conf = $conn->prepare('SELECT user_id FROM tblusers WHERE username = :u AND user_id <> :id LIMIT 1');
        $conf->bindParam(':u', $username);
        $conf->bindParam(':id', $id, PDO::PARAM_INT);
        $conf->execute();
        if ($conf->fetch(PDO::FETCH_ASSOC)){
          return json_encode(['success' => 0, 'message' => 'Username already taken']);
        }
      }
      $sets = [];
      $params = [':id' => $id];
      if ($username !== null){ $sets[] = 'username = :u'; $params[':u'] = $username; }
      if ($role !== null && in_array($role, ['admin','hr','manager','employee'], true)){ $sets[] = 'role = :r'; $params[':r'] = $role; }
      if (array_key_exists('employee_id', $data)){
        if ($employee_id === null){ $sets[] = 'employee_id = NULL'; }
        else { $sets[] = 'employee_id = :eid'; $params[':eid'] = $employee_id; }
      }
      if (empty($sets)) return json_encode(['success' => 1]);
      $sql = 'UPDATE tblusers SET ' . implode(', ', $sets) . ' WHERE user_id = :id';
      $stmt = $conn->prepare($sql);
      foreach ($params as $k=>$v){
        if ($k === ':id') $stmt->bindValue($k, $v, PDO::PARAM_INT);
        else $stmt->bindValue($k, $v);
      }
      $stmt->execute();
      return json_encode(['success' => 1]);
    } catch (Exception $e){
      return json_encode(['success' => 0, 'message' => 'Failed to update user']);
    }
  }

  /**
   * DELETE USER ACCOUNT
   * Removes user from system with safety checks
   * Prevents deletion of own account to avoid lockout
   */
  function deleteUser($conn, $json){
    $data = json_decode($json, true);
    $id = isset($data['user_id']) ? intval($data['user_id']) : 0;
    if ($id <= 0) return json_encode(['success' => 0]);
    // Prevent deleting own account to avoid lockout
    if (isset($_SESSION['user_id']) && intval($_SESSION['user_id']) === $id){
      return json_encode(['success' => 0, 'message' => 'Cannot delete your own account']);
    }
    try {
      $del = $conn->prepare('DELETE FROM tblusers WHERE user_id = :id');
      $del->bindParam(':id', $id, PDO::PARAM_INT);
      $del->execute();
      return json_encode(['success' => $del->rowCount() > 0 ? 1 : 0]);
    } catch (Exception $e){ return json_encode(['success' => 0]); }
  }

  /**
   * ADMIN PASSWORD RESET
   * Resets user password with optional custom password
   * Clears existing reset tokens for security
   */
  function adminResetPassword($conn, $json){
    $data = json_decode($json, true);
    $id = isset($data['user_id']) ? intval($data['user_id']) : 0;
    $newPassword = isset($data['password']) ? (string)$data['password'] : '';
    if ($id <= 0) return json_encode(['success' => 0]);
    try {
      $plain = $newPassword !== '' ? $newPassword : generateRandomPassword(10);
      $hash = password_hash($plain, PASSWORD_DEFAULT);
      $upd = $conn->prepare('UPDATE tblusers SET password = :p, reset_code = NULL, reset_code_expires = NULL WHERE user_id = :id');
      $upd->bindParam(':p', $hash);
      $upd->bindParam(':id', $id, PDO::PARAM_INT);
      $upd->execute();
      return json_encode(['success' => 1, 'generated_password' => ($newPassword === '' ? $plain : null)]);
    } catch (Exception $e){ return json_encode(['success' => 0]); }
  }

  function setMappedEmployeeStatus($conn, $json){
    $data = json_decode($json, true);
    $id = isset($data['user_id']) ? intval($data['user_id']) : 0;
    $status = isset($data['status']) ? strtolower(trim($data['status'])) : '';
    if ($id <= 0 || ($status !== 'active' && $status !== 'inactive')) return json_encode(['success' => 0]);
    try {
      $sel = $conn->prepare('SELECT employee_id FROM tblusers WHERE user_id = :id LIMIT 1');
      $sel->bindParam(':id', $id, PDO::PARAM_INT);
      $sel->execute();
      $row = $sel->fetch(PDO::FETCH_ASSOC);
      if (!$row || !$row['employee_id']) return json_encode(['success' => 0, 'message' => 'User is not linked to an employee']);
      $eid = intval($row['employee_id']);
      $upd = $conn->prepare('UPDATE tblemployees SET status = :s WHERE employee_id = :eid');
      $upd->bindParam(':s', $status);
      $upd->bindParam(':eid', $eid, PDO::PARAM_INT);
      $upd->execute();
      return json_encode(['success' => 1, 'employee_id' => $eid, 'status' => $status]);
    } catch (Exception $e){ return json_encode(['success' => 0]); }
  }

  function generateRandomPassword($length = 10){
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    $max = strlen($alphabet) - 1;
    $out = '';
    for ($i = 0; $i < $length; $i++) {
      $out .= $alphabet[random_int(0, $max)];
    }
    return $out;
  }
?>
