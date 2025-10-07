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

  switch ($operation) {
    case 'getEmployees':
      echo getEmployees($conn);
      break;
    case 'getEmployee':
      echo getEmployee($conn);
      break;
    case 'createEmployee':
      echo createEmployee($conn, $json);
      break;
    case 'updateEmployee':
      echo updateEmployee($conn, $json);
      break;
    case 'deleteEmployee':
      echo deleteEmployee($conn, $json);
      break;
    case 'getDepartments':
      echo getDepartments($conn);
      break;
    case 'getDepartmentPositions':
      echo getDepartmentPositions($conn);
      break;
    case 'addDepartmentPosition':
      echo addDepartmentPosition($conn, $json);
      break;
    case 'deleteDepartmentPosition':
      echo deleteDepartmentPosition($conn, $json);
      break;
    case 'setEmployeeStatus':
      echo setEmployeeStatus($conn, $json);
      break;
    case 'updateProfileImage':
      echo updateProfileImage($conn, $json);
      break;
    case 'getDepartmentsFull':
      echo getDepartmentsFull($conn);
      break;
    case 'createDepartment':
      echo createDepartment($conn, $json);
      break;
    case 'updateDepartment':
      echo updateDepartment($conn, $json);
      break;
    case 'deleteDepartment':
      echo deleteDepartment($conn, $json);
      break;
    default:
      echo json_encode([]);
  }

  /**
   * RETRIEVE ALL EMPLOYEES WITH DETAILS
   * Fetches complete employee data including financial info and user roles
   * Joins employees, financial details, and user tables
   */
  function getEmployees($conn){
    $sql = "SELECT e.*, f.bank_account, f.tax_id, f.sss_number, f.philhealth_number, f.pagibig_number, u.role AS user_role
            FROM tblemployees e
            LEFT JOIN tblemployee_financial_details f ON f.employee_id = e.employee_id
            LEFT JOIN tblusers u ON u.employee_id = e.employee_id
            ORDER BY e.last_name, e.first_name";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return json_encode($rows);
  }

  /**
   * GET SINGLE EMPLOYEE BY ID
   * Retrieves detailed employee information for specific employee
   * Includes financial details and user role information
   */
  function getEmployee($conn){
    $id = isset($_GET['employee_id']) ? intval($_GET['employee_id']) : 0;
    if ($id <= 0) { return json_encode(null); }
    $sql = "SELECT e.*, f.bank_account, f.tax_id, f.sss_number, f.philhealth_number, f.pagibig_number, u.role AS user_role
            FROM tblemployees e
            LEFT JOIN tblemployee_financial_details f ON f.employee_id = e.employee_id
            LEFT JOIN tblusers u ON u.employee_id = e.employee_id
            WHERE e.employee_id = :id
            LIMIT 1";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return json_encode($row ?: null);
  }

  /**
   * CREATE NEW EMPLOYEE RECORD
   * Inserts employee with full profile and financial details
   * Automatically creates user account if role specified
   */
  function createEmployee($conn, $json){
    $data = json_decode($json, true);
    // Normalize optional fields for extended schema
    $data['middle_name'] = isset($data['middle_name']) ? $data['middle_name'] : null;
    $data['date_of_birth'] = (isset($data['date_of_birth']) && $data['date_of_birth'] !== '') ? $data['date_of_birth'] : null;
    $data['gender'] = isset($data['gender']) ? $data['gender'] : null;
    $data['address'] = isset($data['address']) ? $data['address'] : null;
    $data['salary_rate_type'] = isset($data['salary_rate_type']) ? $data['salary_rate_type'] : 'monthly';
    $data['bank_account'] = isset($data['bank_account']) ? $data['bank_account'] : null;
    $data['tax_id'] = isset($data['tax_id']) ? $data['tax_id'] : null;
    $data['sss_number'] = isset($data['sss_number']) ? $data['sss_number'] : null;
    $data['philhealth_number'] = isset($data['philhealth_number']) ? $data['philhealth_number'] : null;
    $data['pagibig_number'] = isset($data['pagibig_number']) ? $data['pagibig_number'] : null;

    $sql = "INSERT INTO tblemployees(first_name, middle_name, last_name, date_of_birth, gender, email, phone, address, department, position, basic_salary, salary_rate_type, date_hired, status)
            VALUES(:first_name, :middle_name, :last_name, :date_of_birth, :gender, :email, :phone, :address, :department, :position, :basic_salary, :salary_rate_type, :date_hired, :status)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':first_name', $data['first_name']);
    $stmt->bindParam(':middle_name', $data['middle_name']);
    $stmt->bindParam(':last_name', $data['last_name']);
    $stmt->bindParam(':date_of_birth', $data['date_of_birth']);
    $stmt->bindParam(':gender', $data['gender']);
    $stmt->bindParam(':email', $data['email']);
    $stmt->bindParam(':phone', $data['phone']);
    $stmt->bindParam(':address', $data['address']);
    $stmt->bindParam(':department', $data['department']);
    $stmt->bindParam(':position', $data['position']);
    $stmt->bindParam(':basic_salary', $data['basic_salary']);
    $stmt->bindParam(':salary_rate_type', $data['salary_rate_type']);
    $date_hired = (isset($data['date_hired']) && $data['date_hired'] !== '') ? $data['date_hired'] : date('Y-m-d');
    $stmt->bindParam(':date_hired', $date_hired);
    $status = (isset($data['status']) && $data['status'] !== '') ? $data['status'] : 'active';
    $stmt->bindParam(':status', $status);
    $stmt->execute();
    $success = $stmt->rowCount() > 0;
    $empId = $success ? (int)$conn->lastInsertId() : null;
    $response = ['success' => $success ? 1 : 0];
    if ($success) { $response['employee_id'] = $empId; 
      // Insert financial details in separate table
      try {
        $insFin = $conn->prepare("INSERT INTO tblemployee_financial_details (employee_id, bank_account, tax_id, sss_number, philhealth_number, pagibig_number) VALUES (:eid, :bank_account, :tax_id, :sss_number, :philhealth_number, :pagibig_number)");
        $insFin->bindParam(':eid', $empId, PDO::PARAM_INT);
        $insFin->bindParam(':bank_account', $data['bank_account']);
        $insFin->bindParam(':tax_id', $data['tax_id']);
        $insFin->bindParam(':sss_number', $data['sss_number']);
        $insFin->bindParam(':philhealth_number', $data['philhealth_number']);
        $insFin->bindParam(':pagibig_number', $data['pagibig_number']);
        $insFin->execute();
      } catch (Exception $e) {
        // ignore insert error
      }
    }
    $roleForAccount = (isset($data['user_role']) && in_array($data['user_role'], ['hr','employee','manager'], true)) ? $data['user_role'] : (isset($data['position']) ? $data['position'] : null);
    if ($success && $roleForAccount && in_array($roleForAccount, ['hr','employee','manager'], true)){
      // Create account with username = email for HR/Employee/Manager when requested
      $email = isset($data['email']) ? trim($data['email']) : '';
      if ($email !== ''){
        $exists = $conn->prepare('SELECT user_id FROM tblusers WHERE username = :u LIMIT 1');
        $exists->bindParam(':u', $email);
        $exists->execute();
        $u = $exists->fetch(PDO::FETCH_ASSOC);
        if (!$u){
          $plain = '';
          if (isset($data['user_password']) && $data['user_password'] !== '') { $plain = $data['user_password']; }
          elseif (isset($data['hr_password']) && $data['hr_password'] !== '') { $plain = $data['hr_password']; }
          else { $plain = generateRandomPassword(10); }
          $hash = password_hash($plain, PASSWORD_DEFAULT);
          $role = ($roleForAccount === 'hr') ? 'hr' : (($roleForAccount === 'manager') ? 'manager' : 'employee');
          $ins = $conn->prepare("INSERT INTO tblusers(username, password, role, employee_id) VALUES(:u, :p, :r, :eid)");
          $ins->bindParam(':u', $email);
          $ins->bindParam(':p', $hash);
          $ins->bindParam(':r', $role);
          $ins->bindParam(':eid', $empId, PDO::PARAM_INT);
          $ins->execute();
          $response['generated_password'] = $plain;
        } else {
          // Ensure mapping and role are correct
          $newRole = ($roleForAccount === 'hr') ? 'hr' : (($roleForAccount === 'manager') ? 'manager' : 'employee');
          $upd = $conn->prepare("UPDATE tblusers SET role=:r, employee_id=:eid WHERE username=:u");
          $upd->bindParam(':eid', $empId, PDO::PARAM_INT);
          $upd->bindParam(':r', $newRole);
          $upd->bindParam(':u', $email);
          $upd->execute();
        }
      }
    }
    return json_encode($response);
  }

  /**
   * UPDATE EXISTING EMPLOYEE RECORD
   * Modifies employee information with upsert capability
   * Handles financial details and user account updates
   */
  function updateEmployee($conn, $json){
    $data = json_decode($json, true);
    // Normalize inputs with safe defaults
    $data['first_name'] = isset($data['first_name']) ? $data['first_name'] : '';
    $data['last_name'] = isset($data['last_name']) ? $data['last_name'] : '';
    $data['email'] = isset($data['email']) ? $data['email'] : '';
    $data['phone'] = isset($data['phone']) ? $data['phone'] : '';
    $data['department'] = isset($data['department']) ? $data['department'] : '';
    $data['position'] = isset($data['position']) ? $data['position'] : 'employee';
    $data['basic_salary'] = isset($data['basic_salary']) ? $data['basic_salary'] : 0;
    $data['date_hired'] = isset($data['date_hired']) ? $data['date_hired'] : null;
    $data['status'] = isset($data['status']) ? $data['status'] : 'active';
    $data['user_role'] = isset($data['user_role']) ? $data['user_role'] : null;
    // Newly supported fields
    $data['middle_name'] = isset($data['middle_name']) ? $data['middle_name'] : null;
    $data['date_of_birth'] = (isset($data['date_of_birth']) && $data['date_of_birth'] !== '') ? $data['date_of_birth'] : null;
    $data['gender'] = isset($data['gender']) ? $data['gender'] : null;
    $data['address'] = isset($data['address']) ? $data['address'] : null;
    $data['salary_rate_type'] = isset($data['salary_rate_type']) ? $data['salary_rate_type'] : 'monthly';
    $data['bank_account'] = isset($data['bank_account']) ? $data['bank_account'] : null;
    $data['tax_id'] = isset($data['tax_id']) ? $data['tax_id'] : null;
    $data['sss_number'] = isset($data['sss_number']) ? $data['sss_number'] : null;
    $data['philhealth_number'] = isset($data['philhealth_number']) ? $data['philhealth_number'] : null;
    $data['pagibig_number'] = isset($data['pagibig_number']) ? $data['pagibig_number'] : null;

    $empId = isset($data['employee_id']) ? intval($data['employee_id']) : 0;
    $inserted = false;
    $success = false;
    $changeItems = [];
    $response = ['success' => 0];

    // If no employee_id provided or employee does not exist, create it (upsert behavior)
    if ($empId <= 0) {
      $ins = $conn->prepare("INSERT INTO tblemployees(first_name, middle_name, last_name, date_of_birth, gender, email, phone, address, department, position, basic_salary, salary_rate_type, date_hired, status)
                             VALUES(:first_name, :middle_name, :last_name, :date_of_birth, :gender, :email, :phone, :address, :department, :position, :basic_salary, :salary_rate_type, :date_hired, :status)");
      $ins->bindParam(':first_name', $data['first_name']);
      $ins->bindParam(':middle_name', $data['middle_name']);
      $ins->bindParam(':last_name', $data['last_name']);
      $ins->bindParam(':date_of_birth', $data['date_of_birth']);
      $ins->bindParam(':gender', $data['gender']);
      $ins->bindParam(':email', $data['email']);
      $ins->bindParam(':phone', $data['phone']);
      $ins->bindParam(':address', $data['address']);
      $ins->bindParam(':department', $data['department']);
      $ins->bindParam(':position', $data['position']);
      $ins->bindParam(':basic_salary', $data['basic_salary']);
      $ins->bindParam(':salary_rate_type', $data['salary_rate_type']);
      $ins->bindParam(':date_hired', $data['date_hired']);
      $ins->bindParam(':status', $data['status']);
      $ins->execute();
      if ($ins->rowCount() > 0) {
        $empId = (int)$conn->lastInsertId();
        $data['employee_id'] = $empId;
        $inserted = true;
        $success = true;
        $response['success'] = 1;
        // Insert financial details
        try {
          $insFin = $conn->prepare("INSERT INTO tblemployee_financial_details (employee_id, bank_account, tax_id, sss_number, philhealth_number, pagibig_number) VALUES (:eid, :bank_account, :tax_id, :sss_number, :philhealth_number, :pagibig_number)");
          $insFin->bindParam(':eid', $empId, PDO::PARAM_INT);
          $insFin->bindParam(':bank_account', $data['bank_account']);
          $insFin->bindParam(':tax_id', $data['tax_id']);
          $insFin->bindParam(':sss_number', $data['sss_number']);
          $insFin->bindParam(':philhealth_number', $data['philhealth_number']);
          $insFin->bindParam(':pagibig_number', $data['pagibig_number']);
          $insFin->execute();
        } catch (Exception $e) {}

        // If a session user exists, map this employee to that user (avoid creating duplicates)
        if (isset($_SESSION['user_id'])) {
          $uid = intval($_SESSION['user_id']);
          $map = $conn->prepare("UPDATE tblusers SET employee_id = :eid WHERE user_id = :uid");
          $map->bindParam(':eid', $empId, PDO::PARAM_INT);
          $map->bindParam(':uid', $uid, PDO::PARAM_INT);
          $map->execute();

          // Optionally sync username to provided email if set and unique
          $email = trim($data['email']);
          if ($email !== '') {
            $conf = $conn->prepare('SELECT user_id FROM tblusers WHERE username = :u LIMIT 1');
            $conf->bindParam(':u', $email);
            $conf->execute();
            $exists = $conf->fetch(PDO::FETCH_ASSOC);
            if (!$exists || intval($exists['user_id']) === $uid) {
              $updU = $conn->prepare("UPDATE tblusers SET username = :u WHERE user_id = :uid");
              $updU->bindParam(':u', $email);
              $updU->bindParam(':uid', $uid, PDO::PARAM_INT);
              $updU->execute();
            }
          }
          // Set role based on position/user_role if provided
          $role = (isset($data['user_role']) && in_array($data['user_role'], ['hr','manager','employee'], true)) ? $data['user_role'] : (($data['position'] === 'hr') ? 'hr' : (($data['position'] === 'manager') ? 'manager' : 'employee'));
          $updRole = $conn->prepare("UPDATE tblusers SET role = :r WHERE user_id = :uid");
          $updRole->bindParam(':r', $role);
          $updRole->bindParam(':uid', $uid, PDO::PARAM_INT);
          $updRole->execute();
        }
      }
    } else {
      // Ensure employee exists; if not, fallback to insert
      $sel = $conn->prepare("SELECT e.*, f.bank_account, f.tax_id, f.sss_number, f.philhealth_number, f.pagibig_number FROM tblemployees e LEFT JOIN tblemployee_financial_details f ON f.employee_id = e.employee_id WHERE e.employee_id = :id LIMIT 1");
      $sel->bindParam(':id', $empId, PDO::PARAM_INT);
      $sel->execute();
      $orig = $sel->fetch(PDO::FETCH_ASSOC);

      if (!$orig) {
        // Insert instead
        $ins = $conn->prepare("INSERT INTO tblemployees(first_name, middle_name, last_name, date_of_birth, gender, email, phone, address, department, position, basic_salary, salary_rate_type, date_hired, status)
                               VALUES(:first_name, :middle_name, :last_name, :date_of_birth, :gender, :email, :phone, :address, :department, :position, :basic_salary, :salary_rate_type, :date_hired, :status)");
        $ins->bindParam(':first_name', $data['first_name']);
        $ins->bindParam(':middle_name', $data['middle_name']);
        $ins->bindParam(':last_name', $data['last_name']);
        $ins->bindParam(':date_of_birth', $data['date_of_birth']);
        $ins->bindParam(':gender', $data['gender']);
        $ins->bindParam(':email', $data['email']);
        $ins->bindParam(':phone', $data['phone']);
        $ins->bindParam(':address', $data['address']);
        $ins->bindParam(':department', $data['department']);
        $ins->bindParam(':position', $data['position']);
        $ins->bindParam(':basic_salary', $data['basic_salary']);
        $ins->bindParam(':salary_rate_type', $data['salary_rate_type']);
        $ins->bindParam(':date_hired', $data['date_hired']);
        $ins->bindParam(':status', $data['status']);
        $ins->execute();
        if ($ins->rowCount() > 0) {
          $empId = (int)$conn->lastInsertId();
          $data['employee_id'] = $empId;
          $inserted = true;
          $success = true;
          $response['success'] = 1;
          // Insert financial details
          try {
            $insFin = $conn->prepare("INSERT INTO tblemployee_financial_details (employee_id, bank_account, tax_id, sss_number, philhealth_number, pagibig_number) VALUES (:eid, :bank_account, :tax_id, :sss_number, :philhealth_number, :pagibig_number)");
            $insFin->bindParam(':eid', $empId, PDO::PARAM_INT);
            $insFin->bindParam(':bank_account', $data['bank_account']);
            $insFin->bindParam(':tax_id', $data['tax_id']);
            $insFin->bindParam(':sss_number', $data['sss_number']);
            $insFin->bindParam(':philhealth_number', $data['philhealth_number']);
            $insFin->bindParam(':pagibig_number', $data['pagibig_number']);
            $insFin->execute();
          } catch (Exception $e) {}
        }
      } else {
        // Perform update
        $sql = "UPDATE tblemployees SET
                  first_name = :first_name,
                  middle_name = :middle_name,
                  last_name = :last_name,
                  date_of_birth = :date_of_birth,
                  gender = :gender,
                  email = :email,
                  phone = :phone,
                  address = :address,
                  department = :department,
                  position = :position,
                  basic_salary = :basic_salary,
                  salary_rate_type = :salary_rate_type,
                  date_hired = :date_hired,
                  status = :status
                WHERE employee_id = :employee_id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':employee_id', $empId, PDO::PARAM_INT);
        $stmt->bindParam(':first_name', $data['first_name']);
        $stmt->bindParam(':middle_name', $data['middle_name']);
        $stmt->bindParam(':last_name', $data['last_name']);
        $stmt->bindParam(':date_of_birth', $data['date_of_birth']);
        $stmt->bindParam(':gender', $data['gender']);
        $stmt->bindParam(':email', $data['email']);
        $stmt->bindParam(':phone', $data['phone']);
        $stmt->bindParam(':address', $data['address']);
        $stmt->bindParam(':department', $data['department']);
        $stmt->bindParam(':position', $data['position']);
        $stmt->bindParam(':basic_salary', $data['basic_salary']);
        $stmt->bindParam(':salary_rate_type', $data['salary_rate_type']);
        $stmt->bindParam(':date_hired', $data['date_hired']);
        $stmt->bindParam(':status', $data['status']);
        $stmt->execute();
        // Upsert financial details into separate table
        try {
          $finUp = $conn->prepare("INSERT INTO tblemployee_financial_details (employee_id, bank_account, tax_id, sss_number, philhealth_number, pagibig_number) VALUES (:eid, :bank_account, :tax_id, :sss_number, :philhealth_number, :pagibig_number) ON DUPLICATE KEY UPDATE bank_account = VALUES(bank_account), tax_id = VALUES(tax_id), sss_number = VALUES(sss_number), philhealth_number = VALUES(philhealth_number), pagibig_number = VALUES(pagibig_number)");
          $finUp->bindParam(':eid', $empId, PDO::PARAM_INT);
          $finUp->bindParam(':bank_account', $data['bank_account']);
          $finUp->bindParam(':tax_id', $data['tax_id']);
          $finUp->bindParam(':sss_number', $data['sss_number']);
          $finUp->bindParam(':philhealth_number', $data['philhealth_number']);
          $finUp->bindParam(':pagibig_number', $data['pagibig_number']);
          $finUp->execute();
        } catch (Exception $e) {}
        $success = $stmt->rowCount() >= 0; // treat as success even if values unchanged
        $response['success'] = $success ? 1 : 0;

        // Build change list for notification
        if (is_array($orig)) {
          $fields = [
            'first_name' => 'First name',
            'middle_name' => 'Middle name',
            'last_name' => 'Last name',
            'email' => 'Email',
            'phone' => 'Phone',
            'address' => 'Address',
            'department' => 'Department',
            'position' => 'Position',
            'basic_salary' => 'Basic salary',
            'salary_rate_type' => 'Salary rate',
            'date_hired' => 'Date hired',
            'status' => 'Status',
            'gender' => 'Gender',
            'date_of_birth' => 'Date of birth',
            'bank_account' => 'Bank account',
            'tax_id' => 'Tax ID',
            'sss_number' => 'SSS Number',
            'philhealth_number' => 'PhilHealth Number',
            'pagibig_number' => 'Pag-IBIG Number'
          ];
          foreach ($fields as $key => $label) {
            $old = isset($orig[$key]) ? trim((string)$orig[$key]) : '';
            $new = isset($data[$key]) ? trim((string)$data[$key]) : '';
            if ($old !== $new) {
              $dispOld = $old === '' ? '(empty)' : $old;
              $dispNew = $new === '' ? '(empty)' : $new;
              $changeItems[] = $label . ': ' . $dispOld . ' -> ' . $dispNew;
            }
          }
        }
      }
    }
    
    // Add notification describing what changed (only on meaningful events)
    if ($success) {
      try {
        $eid = intval($data['employee_id']);
        $type = 'profile_update';
        $actor = isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : null;
        $message = '';

        if ($inserted) {
          $message = 'Your profile has been created.';
        } else {
          if (is_array($changeItems) && count($changeItems) > 0) {
            $summary = implode('; ', $changeItems);
            if (strlen($summary) > 230) { // keep within VARCHAR(255)
              $summary = substr($summary, 0, 227) . '...';
            }
            $message = 'Profile updated: ' . $summary;
          } else {
            $message = '';
          }
        }

        if ($message !== '') {
          $ins = $conn->prepare('INSERT INTO tblnotifications(employee_id, message, type, actor_user_id) VALUES(:eid, :msg, :type, :actor)');
          $ins->bindParam(':eid', $eid, PDO::PARAM_INT);
          $ins->bindParam(':msg', $message);
          $ins->bindParam(':type', $type);
          if ($actor !== null) {
            $ins->bindParam(':actor', $actor, PDO::PARAM_INT);
          } else {
            $null = null;
            $ins->bindParam(':actor', $null, PDO::PARAM_NULL);
          }
          $ins->execute();
          $response['notification_created'] = true;
        }
      } catch (Exception $e) {
        $response['notification_error'] = $e->getMessage();
      }
    }
    
    // Keep login in sync with employee email (for both HR and Employee accounts)
    $email = isset($data['email']) ? trim($data['email']) : '';
    $empId = isset($data['employee_id']) ? intval($data['employee_id']) : 0;
    // Accept password from either user_password or hr_password (UI sends user_password)
    $plainPwd = '';
    if (isset($data['user_password']) && trim($data['user_password']) !== '') {
      $plainPwd = trim($data['user_password']);
    } elseif (isset($data['hr_password']) && trim($data['hr_password']) !== '') {
      $plainPwd = trim($data['hr_password']);
    }
    if ($email !== '' && $empId > 0){
      // Find any user mapped to this employee (hr or employee)
      $byEmp = $conn->prepare("SELECT user_id, username, role FROM tblusers WHERE employee_id = :eid LIMIT 1");
      $byEmp->bindParam(':eid', $empId, PDO::PARAM_INT);
      $byEmp->execute();
      $mapped = $byEmp->fetch(PDO::FETCH_ASSOC);

      if ($mapped){
        if (strcasecmp($mapped['username'], $email) !== 0){
          $conf = $conn->prepare('SELECT user_id FROM tblusers WHERE username = :u LIMIT 1');
          $conf->bindParam(':u', $email);
          $conf->execute();
          $confRow = $conf->fetch(PDO::FETCH_ASSOC);
          if (!$confRow || intval($confRow['user_id']) === intval($mapped['user_id'])){
            $updUser = $conn->prepare("UPDATE tblusers SET username = :u WHERE user_id = :id");
            $updUser->bindParam(':u', $email);
            $updUser->bindParam(':id', $mapped['user_id'], PDO::PARAM_INT);
            $updUser->execute();
            $response['username_updated'] = true;
            $mapped['username'] = $email;
          } else {
            $response['username_conflict'] = true;
          }
        }
        if ($plainPwd !== ''){
          $hash = password_hash($plainPwd, PASSWORD_DEFAULT);
          $updPwd = $conn->prepare("UPDATE tblusers SET password = :p WHERE user_id = :id");
          $updPwd->bindParam(':p', $hash);
          $updPwd->bindParam(':id', $mapped['user_id'], PDO::PARAM_INT);
          $updPwd->execute();
          $response['password_updated'] = true;
        }
        $response['effective_username'] = $mapped['username'];
        
        // Ensure user role matches employee position/user_role
        $targetRole = (isset($data['user_role']) && in_array($data['user_role'], ['hr','manager','employee'], true)) ? $data['user_role'] : (($data['position'] === 'hr') ? 'hr' : (($data['position'] === 'manager') ? 'manager' : 'employee'));
        if (strtolower($mapped['role']) !== $targetRole) {
          $updRole = $conn->prepare("UPDATE tblusers SET role = :r WHERE user_id = :id");
          $updRole->bindParam(':r', $targetRole);
          $updRole->bindParam(':id', $mapped['user_id'], PDO::PARAM_INT);
          $updRole->execute();
          $mapped['role'] = $targetRole;
          $response['role_updated'] = true;
        }
        
        // Return updated user information for frontend sync
        $response['updated_user'] = [
          'user_id' => $mapped['user_id'],
          'username' => $mapped['username'],
          'role' => $mapped['role'],
          'employee_id' => $empId
        ];
        
        // Also return updated employee information
        $response['updated_employee'] = [
          'employee_id' => $empId,
          'first_name' => $data['first_name'],
          'last_name' => $data['last_name'],
          'email' => $data['email'],
          'phone' => $data['phone'],
          'department' => $data['department'],
          'position' => $data['position']
        ];
      } else {
        // If no mapped user yet, create based on position/user_role
        $roleForAccount = (isset($data['user_role']) && in_array($data['user_role'], ['hr','employee','manager'], true)) ? $data['user_role'] : (isset($data['position']) ? $data['position'] : null);
        if ($roleForAccount === 'hr') {
          // Try to map pre-seeded HR user without employee_id
          $byPrev = $conn->prepare("SELECT user_id FROM tblusers WHERE employee_id IS NULL AND role = 'hr' AND username != :u LIMIT 1");
          $byPrev->bindParam(':u', $email);
          $byPrev->execute();
          $prev = $byPrev->fetch(PDO::FETCH_ASSOC);
          if ($prev){
            $updPrev = $conn->prepare("UPDATE tblusers SET username = :u, employee_id = :eid WHERE user_id = :id");
            $updPrev->bindParam(':u', $email);
            $updPrev->bindParam(':eid', $empId, PDO::PARAM_INT);
            $updPrev->bindParam(':id', $prev['user_id'], PDO::PARAM_INT);
            $updPrev->execute();
            $response['username_updated'] = true;
            if ($plainPwd !== ''){
              $hash = password_hash($plainPwd, PASSWORD_DEFAULT);
              $updPwd = $conn->prepare("UPDATE tblusers SET password = :p WHERE user_id = :id");
              $updPwd->bindParam(':p', $hash);
              $updPwd->bindParam(':id', $prev['user_id'], PDO::PARAM_INT);
              $updPwd->execute();
              $response['password_updated'] = true;
            }
            $response['effective_username'] = $email;
          } else {
            $plain = $plainPwd !== '' ? $plainPwd : generateRandomPassword(10);
            $hash = password_hash($plain, PASSWORD_DEFAULT);
            $ins = $conn->prepare("INSERT INTO tblusers(username, password, role, employee_id) VALUES(:u, :p, 'hr', :eid)");
            $ins->bindParam(':u', $email);
            $ins->bindParam(':p', $hash);
            $ins->bindParam(':eid', $empId, PDO::PARAM_INT);
            $ins->execute();
            $response['generated_password'] = $plain;
            $response['effective_username'] = $email;
          }
        } elseif ($roleForAccount === 'manager') {
          $plain = $plainPwd !== '' ? $plainPwd : generateRandomPassword(10);
          $hash = password_hash($plain, PASSWORD_DEFAULT);
          $ins = $conn->prepare("INSERT INTO tblusers(username, password, role, employee_id) VALUES(:u, :p, 'manager', :eid)");
          $ins->bindParam(':u', $email);
          $ins->bindParam(':p', $hash);
          $ins->bindParam(':eid', $empId, PDO::PARAM_INT);
          $ins->execute();
          $response['generated_password'] = $plain;
          $response['effective_username'] = $email;
        } elseif ($roleForAccount === 'employee') {
          $plain = $plainPwd !== '' ? $plainPwd : generateRandomPassword(10);
          $hash = password_hash($plain, PASSWORD_DEFAULT);
          $ins = $conn->prepare("INSERT INTO tblusers(username, password, role, employee_id) VALUES(:u, :p, 'employee', :eid)");
          $ins->bindParam(':u', $email);
          $ins->bindParam(':p', $hash);
          $ins->bindParam(':eid', $empId, PDO::PARAM_INT);
          $ins->execute();
          $response['generated_password'] = $plain;
          $response['effective_username'] = $email;
        }
      }
    }
    return json_encode($response);
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

  function deleteEmployee($conn, $json){
    $data = json_decode($json, true);
    $sql = "DELETE FROM tblemployees WHERE employee_id = :employee_id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':employee_id', $data['employee_id']);
    $stmt->execute();
    return json_encode($stmt->rowCount() > 0 ? 1 : 0);
  }
function setEmployeeStatus($conn, $json){
    $data = json_decode($json, true);
    $empId = isset($data['employee_id']) ? intval($data['employee_id']) : 0;
    $status = isset($data['status']) ? strtolower(trim($data['status'])) : '';
    if ($empId <= 0 || ($status !== 'active' && $status !== 'inactive')){
      return json_encode(['success' => 0]);
    }
    $stmt = $conn->prepare("UPDATE tblemployees SET status = :status WHERE employee_id = :id");
    $stmt->bindParam(':status', $status);
    $stmt->bindParam(':id', $empId, PDO::PARAM_INT);
    $stmt->execute();
    return json_encode(['success' => $stmt->rowCount() >= 0 ? 1 : 0, 'status' => $status]);
  }

function updateProfileImage($conn, $json){
    $data = json_decode($json, true);
    $empId = isset($data['employee_id']) ? intval($data['employee_id']) : 0;
    $img = isset($data['profile_image']) ? trim($data['profile_image']) : '';
    if ($empId <= 0){
      return json_encode(['success' => 0, 'message' => 'Invalid employee']);
    }
    try {
      if ($img !== '' && !preg_match('/^data:image\/(png|jpe?g|gif);base64,/i', $img)){
        return json_encode(['success' => 0, 'message' => 'Invalid image format']);
      }
      $stmt = $conn->prepare("UPDATE tblemployees SET profile_image = :img WHERE employee_id = :id");
      if ($img === ''){
        $null = null;
        $stmt->bindParam(':img', $null, PDO::PARAM_NULL);
      } else {
        $stmt->bindParam(':img', $img, PDO::PARAM_STR);
      }
      $stmt->bindParam(':id', $empId, PDO::PARAM_INT);
      $stmt->execute();
      return json_encode(['success' => 1]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Failed to update image']);
    }
  }

function getDepartments($conn){
    try {
      $sql = "SELECT dept_name FROM tbldepartments ORDER BY dept_name";
      $stmt = $conn->prepare($sql);
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);
      return json_encode($rows);
    } catch (Exception $e) {
      return json_encode([]);
    }
  }

function getDepartmentsFull($conn){
    try {
      $sql = "SELECT dept_id, dept_name, description, created_at FROM tbldepartments ORDER BY dept_name";
      $stmt = $conn->prepare($sql);
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
      return json_encode($rows ?: []);
    } catch (Exception $e) {
      return json_encode([]);
    }
  }

function createDepartment($conn, $json){
    try {
      $data = json_decode($json, true);
      $name = isset($data['dept_name']) ? trim($data['dept_name']) : '';
      $desc = isset($data['description']) ? trim($data['description']) : null;
      if ($name === '') {
        return json_encode(['success' => 0, 'message' => 'Department name is required']);
      }
      // Check for existing (case-insensitive)
      $chk = $conn->prepare("SELECT dept_id FROM tbldepartments WHERE LOWER(dept_name) = LOWER(:n) LIMIT 1");
      $chk->bindParam(':n', $name);
      $chk->execute();
      $ex = $chk->fetch(PDO::FETCH_ASSOC);
      if ($ex) {
        return json_encode(['success' => 0, 'message' => 'Department already exists']);
      }
      $stmt = $conn->prepare("INSERT INTO tbldepartments (dept_name, description) VALUES (:n, :d)");
      $stmt->bindParam(':n', $name);
      if ($desc === null || $desc === '') {
        $stmt->bindValue(':d', null, PDO::PARAM_NULL);
      } else {
        $stmt->bindParam(':d', $desc);
      }
      $stmt->execute();
      return json_encode(['success' => 1, 'dept_id' => (int)$conn->lastInsertId()]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Failed to create']);
    }
  }

function updateDepartment($conn, $json){
    try {
      $data = json_decode($json, true);
      $id = isset($data['dept_id']) ? intval($data['dept_id']) : 0;
      $name = isset($data['dept_name']) ? trim($data['dept_name']) : '';
      $desc = isset($data['description']) ? trim($data['description']) : null;
      if ($id <= 0 || $name === '') {
        return json_encode(['success' => 0, 'message' => 'Invalid input']);
      }
      // Ensure unique name
      $chk = $conn->prepare("SELECT dept_id FROM tbldepartments WHERE LOWER(dept_name) = LOWER(:n) AND dept_id <> :id LIMIT 1");
      $chk->bindParam(':n', $name);
      $chk->bindParam(':id', $id, PDO::PARAM_INT);
      $chk->execute();
      $ex = $chk->fetch(PDO::FETCH_ASSOC);
      if ($ex) {
        return json_encode(['success' => 0, 'message' => 'Another department with this name exists']);
      }
      $stmt = $conn->prepare("UPDATE tbldepartments SET dept_name = :n, description = :d WHERE dept_id = :id");
      $stmt->bindParam(':n', $name);
      if ($desc === null || $desc === '') {
        $stmt->bindValue(':d', null, PDO::PARAM_NULL);
      } else {
        $stmt->bindParam(':d', $desc);
      }
      $stmt->bindParam(':id', $id, PDO::PARAM_INT);
      $stmt->execute();
      return json_encode(['success' => 1]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Failed to update']);
    }
  }

function deleteDepartment($conn, $json){
    try {
      $data = json_decode($json, true);
      $id = isset($data['dept_id']) ? intval($data['dept_id']) : 0;
      if ($id <= 0) {
        return json_encode(['success' => 0, 'message' => 'Invalid department']);
      }
      $stmt = $conn->prepare("DELETE FROM tbldepartments WHERE dept_id = :id");
      $stmt->bindParam(':id', $id, PDO::PARAM_INT);
      $stmt->execute();
      return json_encode(['success' => 1]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Failed to delete']);
    }
  }

function getDepartmentPositions($conn){
    try {
      $dept = isset($_GET['dept_name']) ? trim($_GET['dept_name']) : '';
      if ($dept === '') return json_encode([]);
      // Join using dept_id foreign key; case-insensitive match by dept_name
      $sql = "SELECT p.position_name
              FROM tbldepartment_positions p
              JOIN tbldepartments d ON d.dept_id = p.dept_id
              WHERE LOWER(d.dept_name) = LOWER(:d)
              ORDER BY p.position_name";
      $stmt = $conn->prepare($sql);
      $stmt->bindParam(':d', $dept);
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);
      return json_encode($rows ?: []);
    } catch (Exception $e) {
      // If table does not exist or other error, return empty array
      return json_encode([]);
    }
  }

function addDepartmentPosition($conn, $json){
    try {
      $data = json_decode($json, true);
      $deptId = isset($data['dept_id']) ? (int)$data['dept_id'] : 0;
      $position = isset($data['position_name']) ? trim($data['position_name']) : '';
      if ($deptId <= 0 || $position === '') {
        return json_encode(['success' => 0, 'message' => 'Invalid input']);
      }
      // Ensure department exists
      $chkDept = $conn->prepare('SELECT dept_id FROM tbldepartments WHERE dept_id = :id');
      $chkDept->bindParam(':id', $deptId, PDO::PARAM_INT);
      $chkDept->execute();
      if (!$chkDept->fetch(PDO::FETCH_ASSOC)) { return json_encode(['success' => 0, 'message' => 'Department not found']); }
      // Insert ignore duplicate by unique key
      $stmt = $conn->prepare('INSERT INTO tbldepartment_positions (dept_id, position_name) VALUES (:dept_id, :position)');
      $stmt->bindParam(':dept_id', $deptId, PDO::PARAM_INT);
      $stmt->bindParam(':position', $position);
      try {
        $stmt->execute();
      } catch (PDOException $e) {
        if ((int)$e->getCode() === 23000) {
          return json_encode(['success' => 0, 'message' => 'Position already exists']);
        }
        throw $e;
      }
      return json_encode(['success' => 1]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Failed to add position']);
    }
  }

function deleteDepartmentPosition($conn, $json){
    try {
      $data = json_decode($json, true);
      $deptId = isset($data['dept_id']) ? (int)$data['dept_id'] : 0;
      $position = isset($data['position_name']) ? trim($data['position_name']) : '';
      if ($deptId <= 0 || $position === '') { return json_encode(['success' => 0]); }
      $stmt = $conn->prepare('DELETE FROM tbldepartment_positions WHERE dept_id = :dept_id AND position_name = :pos');
      $stmt->bindParam(':dept_id', $deptId, PDO::PARAM_INT);
      $stmt->bindParam(':pos', $position);
      $stmt->execute();
      return json_encode(['success' => 1]);
    } catch (Exception $e) {
      return json_encode(['success' => 0]);
    }
  }

?>


