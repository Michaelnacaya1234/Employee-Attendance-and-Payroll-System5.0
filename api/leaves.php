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
  } else if($_SERVER['REQUEST_METHOD'] == 'POST'){
    $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
    $json = isset($_POST['json']) ? $_POST['json'] : '';
  }

  switch ($operation) {
    case 'listRecent':
      echo listRecent($conn);
      break;
    case 'listPending':
      echo listPending($conn);
      break;
    case 'listApproved':
      echo listApproved($conn);
      break;
    case 'requestLeave':
      echo requestLeave($conn, $json);
      break;
    case 'listByEmployee':
      echo listByEmployee($conn);
      break;
    case 'approve':
      echo setStatus($conn, $json, 'approved');
      break;
    case 'reject':
      echo setStatus($conn, $json, 'rejected');
      break;
    case 'cancel':
      echo cancelLeave($conn, $json);
      break;
    case 'updateLeave':
      echo updateLeave($conn, $json);
      break;
    case 'archiveLeaveBulk':
      echo archiveLeaveBulk($conn, $json);
      break;
    case 'listLeaveArchive':
      echo listLeaveArchive($conn);
      break;
    case 'unarchiveAllLeaves':
      echo unarchiveAllLeaves($conn);
      break;
    default:
      echo json_encode([]);
  }

  /**
   * GET RECENT LEAVE REQUESTS
   * Retrieves latest 20 leave requests with employee and approver details
   * Shows all statuses ordered by creation date
   */
  function listRecent($conn){
    $sql = "SELECT l.*, e.first_name, e.last_name,
                   u1.username AS approved_by_username,
                   u2.username AS rejected_by_username
            FROM tblleaves l
            INNER JOIN tblemployees e ON e.employee_id = l.employee_id
            LEFT JOIN tblusers u1 ON u1.user_id = l.approved_by
            LEFT JOIN tblusers u2 ON u2.user_id = l.rejected_by
            LEFT JOIN tblleave_archive a ON a.leave_id = l.leave_id
            WHERE a.leave_id IS NULL
            ORDER BY l.created_at DESC LIMIT 20";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    return json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
  }

  /**
   * GET PENDING LEAVE REQUESTS
   * Fetches all pending leave requests awaiting approval
   * Ordered by submission date for processing priority
   */
  function listPending($conn){
    $sql = "SELECT l.*, e.first_name, e.last_name FROM tblleaves l
            INNER JOIN tblemployees e ON e.employee_id = l.employee_id
            WHERE l.status = 'pending'
            ORDER BY l.created_at ASC";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    return json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
  }

  /**
   * GET APPROVED LEAVE REQUESTS
   * Retrieves approved leaves with optional date range filtering
   * Supports overlap detection for scheduling conflicts
   */
  function listApproved($conn){
    // Optionally accept overlap filter by a specific date or date range
    $start = isset($_GET['start_date']) ? $_GET['start_date'] : null;
    $end = isset($_GET['end_date']) ? $_GET['end_date'] : null;
    if ($start && !$end) { $end = $start; }

    if ($start && $end) {
      // Overlap condition: leave where (start_date <= end) AND (end_date >= start)
      $sql = "SELECT l.*, e.first_name, e.last_name, e.position
              FROM tblleaves l
              INNER JOIN tblemployees e ON e.employee_id = l.employee_id
              WHERE l.status = 'approved' AND l.start_date <= :end AND l.end_date >= :start
              ORDER BY l.start_date DESC, l.end_date DESC, l.created_at DESC";
      $stmt = $conn->prepare($sql);
      $stmt->bindParam(':start', $start);
      $stmt->bindParam(':end', $end);
      $stmt->execute();
      return json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    $sql = "SELECT l.*, e.first_name, e.last_name, e.position
            FROM tblleaves l
            INNER JOIN tblemployees e ON e.employee_id = l.employee_id
            WHERE l.status = 'approved'
            ORDER BY l.start_date DESC, l.end_date DESC, l.created_at DESC";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    return json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
  }

  /**
   * SUBMIT NEW LEAVE REQUEST
   * Creates leave request with automatic employee ID resolution
   * Validates leave type against system configurations
   */
  function requestLeave($conn, $json){
    $data = json_decode($json, true);
    $employee_id = isset($data['employee_id']) ? intval($data['employee_id']) : 0;
    if ($employee_id <= 0 && isset($_SESSION['user_id'])){
      // Fallback: derive employee_id from logged-in user
      $u = $conn->prepare('SELECT employee_id FROM tblusers WHERE user_id = :id LIMIT 1');
      $u->bindParam(':id', $_SESSION['user_id'], PDO::PARAM_INT);
      $u->execute();
      $row = $u->fetch(PDO::FETCH_ASSOC);
      if ($row && intval($row['employee_id']) > 0){ $employee_id = intval($row['employee_id']); }
    }
    if ($employee_id <= 0){
      return json_encode(['success' => 0, 'message' => 'No employee mapping']);
    }
    // Ensure schema supports dynamic leave types (convert ENUM -> VARCHAR if needed)
    try { ensureLeaveTypeColumnsAreVarchar($conn); } catch (Exception $e) {}
    // Normalize and validate leave_type against allowed values from DB (fallback to defaults)
    $leaveType = normalizeLeaveType($conn, isset($data['leave_type']) ? $data['leave_type'] : '', 'vacation');
    $sql = "INSERT INTO tblleaves(employee_id, start_date, end_date, reason, leave_type, status)
            VALUES(:employee_id, :start, :end, :reason, :leave_type, 'pending')";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':employee_id', $employee_id, PDO::PARAM_INT);
    $stmt->bindParam(':start', $data['start_date']);
    $stmt->bindParam(':end', $data['end_date']);
    $stmt->bindParam(':reason', $data['reason']);
    $stmt->bindParam(':leave_type', $leaveType);
    try {
      $stmt->execute();
    } catch (PDOException $e) {
      try { ensureLeaveTypeColumnsAreVarchar($conn); } catch (Exception $e2) {}
      try { $stmt->execute(); } catch (PDOException $e3) { return json_encode(['success' => 0, 'message' => 'Failed to submit leave', 'error' => $e3->getMessage()]); }
    }

    $ok = $stmt->rowCount() > 0;

    if ($ok) {
      try {
        $empInfo = $conn->prepare('SELECT first_name, last_name, department FROM tblemployees WHERE employee_id = :id LIMIT 1');
        $empInfo->bindParam(':id', $employee_id, PDO::PARAM_INT);
        $empInfo->execute();
        $empRow = $empInfo->fetch(PDO::FETCH_ASSOC) ?: [];

        $first = isset($empRow['first_name']) ? trim($empRow['first_name']) : '';
        $last = isset($empRow['last_name']) ? trim($empRow['last_name']) : '';
        $fullName = trim(($first . ' ' . $last));
        if ($fullName === '') { $fullName = 'Employee #' . $employee_id; }

        $deptRaw = isset($empRow['department']) ? strtolower(trim($empRow['department'])) : '';
        $range = '';
        if (!empty($data['start_date']) && !empty($data['end_date'])) {
          $range = ($data['start_date'] === $data['end_date']) ? $data['start_date'] : ($data['start_date'] . ' → ' . $data['end_date']);
        }
        // Default message: employee submitted their own leave
        $message = $fullName . ' submitted a leave request' . ($range !== '' ? ' (' . $range . ')' : '');
        // If a manager filed on behalf of the employee, use manager-style wording similar to OT/UT
        try {
          $actorUserId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
          if ($actorUserId) {
            $u = $conn->prepare("SELECT role, employee_id FROM tblusers WHERE user_id = :uid LIMIT 1");
            $u->bindParam(':uid', $actorUserId, PDO::PARAM_INT);
            $u->execute();
            $urow = $u->fetch(PDO::FETCH_ASSOC);
            $isManager = $urow && strtolower($urow['role']) === 'manager';
            $actorEmpId = ($urow && !empty($urow['employee_id'])) ? (int)$urow['employee_id'] : 0;
            if ($isManager && $actorEmpId > 0 && $actorEmpId !== (int)$employee_id) {
              // Build manager + employee names
              $mgrName = 'Manager';
              try {
                $me = $conn->prepare("SELECT first_name, last_name FROM tblemployees WHERE employee_id = :eid LIMIT 1");
                $me->bindParam(':eid', $actorEmpId, PDO::PARAM_INT);
                $me->execute();
                $mer = $me->fetch(PDO::FETCH_ASSOC);
                if ($mer) {
                  $mFirst = isset($mer['first_name']) ? trim($mer['first_name']) : '';
                  $mLast = isset($mer['last_name']) ? trim($mer['last_name']) : '';
                  $mn = trim($mFirst . ' ' . $mLast);
                  if ($mn !== '') { $mgrName = $mn; }
                }
              } catch (Exception $e) {}
              $empName = $fullName !== '' ? $fullName : ('Employee #' . (int)$employee_id);
              $on = $range !== '' ? $range : '';
              $message = "Manager {$mgrName} requested leave for {$empName}" . ($on !== '' ? " on {$on}" : '');
            }
          }
        } catch (Exception $e) { /* ignore and keep default message */ }
        // Append reason if provided
        $reasonText = isset($data['reason']) ? trim($data['reason']) : '';
        if ($reasonText !== '') { $message .= ' — Reason: ' . $reasonText; }

        $recipientIds = [];

        $mgrSql = "SELECT u.employee_id FROM tblusers u LEFT JOIN tblemployees e ON e.employee_id = u.employee_id WHERE u.role = 'manager' AND u.employee_id IS NOT NULL";
        if ($deptRaw !== '') {
          $mgrSql .= " AND LOWER(e.department) = :dept";
        }
        $mgrStmt = $conn->prepare($mgrSql);
        if ($deptRaw !== '') { $mgrStmt->bindParam(':dept', $deptRaw, PDO::PARAM_STR); }
        $mgrStmt->execute();
        $mgrRows = $mgrStmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($mgrRows as $row) {
          if (isset($row['employee_id'])) { $recipientIds[] = (int)$row['employee_id']; }
        }

        $hrStmt = $conn->prepare("SELECT employee_id FROM tblusers WHERE role = 'hr' AND employee_id IS NOT NULL");
        $hrStmt->execute();
        $hrRows = $hrStmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($hrRows as $row) {
          if (isset($row['employee_id'])) { $recipientIds[] = (int)$row['employee_id']; }
        }

        $recipientIds = array_values(array_unique(array_filter($recipientIds, function($rid) use ($employee_id) {
          return $rid > 0 && $rid !== (int)$employee_id;
        })));

        if (!empty($recipientIds)) {
          $actorUserId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
          $insNotif = $conn->prepare('INSERT INTO tblnotifications(employee_id, message, type, actor_user_id) VALUES(:eid, :msg, :type, :actor)');
          foreach ($recipientIds as $rid) {
            try {
              $insNotif->bindValue(':eid', $rid, PDO::PARAM_INT);
              $insNotif->bindValue(':msg', $message, PDO::PARAM_STR);
              $insNotif->bindValue(':type', 'leave_request', PDO::PARAM_STR);
              if ($actorUserId !== null) {
                $insNotif->bindValue(':actor', $actorUserId, PDO::PARAM_INT);
              } else {
                $insNotif->bindValue(':actor', null, PDO::PARAM_NULL);
              }
              $insNotif->execute();
              $insNotif->closeCursor();
            } catch (Exception $e) {}
          }
        }
      } catch (Exception $e) { /* ignore notification errors */ }
    }

    return json_encode(['success' => $ok ? 1 : 0]);
  }

  /**
   * GET EMPLOYEE LEAVE HISTORY
   * Retrieves leave records for specific employee
   * Includes approval/rejection details and actor information
   */
  function listByEmployee($conn){
    $employee_id = isset($_GET['employee_id']) ? intval($_GET['employee_id']) : 0;
    if ($employee_id <= 0) return json_encode([]);
    $sql = "SELECT l.*, u1.username AS approved_by_username, u2.username AS rejected_by_username FROM tblleaves l
            LEFT JOIN tblusers u1 ON u1.user_id = l.approved_by
            LEFT JOIN tblusers u2 ON u2.user_id = l.rejected_by
            WHERE l.employee_id = :eid
            ORDER BY l.created_at DESC LIMIT 50";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':eid', $employee_id, PDO::PARAM_INT);
    $stmt->execute();
    return json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
  }

  /**
   * UPDATE LEAVE REQUEST STATUS
   * Approves or rejects leave requests with audit trail
   * Creates notifications and attendance records for approved leaves
   */
  function setStatus($conn, $json, $status){
    $data = json_decode($json, true);
    $note = isset($data['note']) ? trim($data['note']) : '';
    $actor = isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : null;
    $setExtra = '';
    if ($status === 'approved') {
      $setExtra = ', approved_by = :actor, approved_at = NOW(), rejected_by = NULL, rejected_at = NULL';
    } else if ($status === 'rejected') {
      $setExtra = ', rejected_by = :actor, rejected_at = NOW(), approved_by = NULL, approved_at = NULL';
    }
    $sql = "UPDATE tblleaves SET status = :status" . $setExtra . " WHERE leave_id = :id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':status', $status);
    $stmt->bindParam(':id', $data['leave_id']);
    // Ensure :actor is always bound when present in SQL, even if null
    if (strpos($setExtra, ':actor') !== false) {
      if ($actor !== null) { $stmt->bindParam(':actor', $actor, PDO::PARAM_INT); }
      else { $null = null; $stmt->bindParam(':actor', $null, PDO::PARAM_NULL); }
    }
    $stmt->execute();
    $ok = $stmt->rowCount() > 0;

    // Push a notification to the employee and, if approved, record attendance as 'leave'
    if ($ok) {
      try {
        $sel = $conn->prepare('SELECT employee_id, start_date, end_date FROM tblleaves WHERE leave_id = :id LIMIT 1');
        $sel->bindParam(':id', $data['leave_id'], PDO::PARAM_INT);
        $sel->execute();
        $row = $sel->fetch(PDO::FETCH_ASSOC);
        if ($row && intval($row['employee_id']) > 0) {
          $eid = intval($row['employee_id']);
          $message = $status === 'approved' ? 'Your leave request was approved' : 'Your leave request was rejected';
          if ($note !== '') { $message .= ' — Manager note: ' . $note; }
          $ins = $conn->prepare('INSERT INTO tblnotifications(employee_id, message, type, actor_user_id) VALUES(:eid, :msg, :type, :actor)');
          $type = $status;
          $ins->bindParam(':eid', $eid, PDO::PARAM_INT);
          $ins->bindParam(':msg', $message);
          $ins->bindParam(':type', $type);
          if ($actor !== null) { $ins->bindParam(':actor', $actor, PDO::PARAM_INT); } else { $null = null; $ins->bindParam(':actor', $null, PDO::PARAM_NULL); }
          $ins->execute();

          // If approved, create attendance rows for each date in leave period with status 'leave'
          if ($status === 'approved') {
            $start = isset($row['start_date']) ? $row['start_date'] : null;
            $end = isset($row['end_date']) ? $row['end_date'] : null;
            if ($start && $end) {
              try {
                $startDt = new DateTime($start);
                $endDt = new DateTime($end);
                $endDt->setTime(0,0,0);
                $period = new DatePeriod($startDt, new DateInterval('P1D'), (clone $endDt)->modify('+1 day'));
                foreach ($period as $d) {
                  $ds = $d->format('Y-m-d');
                  // Skip if already has attendance for this date
                  $chk = $conn->prepare('SELECT attendance_id FROM tblattendance WHERE employee_id = :eid AND attendance_date = :d LIMIT 1');
                  $chk->bindParam(':eid', $eid, PDO::PARAM_INT);
                  $chk->bindParam(':d', $ds);
                  $chk->execute();
                  if (!$chk->fetch(PDO::FETCH_ASSOC)) {
                    $insA = $conn->prepare("INSERT INTO tblattendance(employee_id, attendance_date, time_in, time_out, status, remarks) VALUES(:eid, :d, NULL, NULL, 'leave', 'Leave approved')");
                    $insA->bindParam(':eid', $eid, PDO::PARAM_INT);
                    $insA->bindParam(':d', $ds);
                    $insA->execute();
                  }
                }
              } catch (Exception $e) { /* ignore attendance insert errors */ }
            }
          }
        }
      } catch (Exception $e) { /* ignore notification/attendance errors */ }
    }

    return json_encode($ok ? 1 : 0);
  }

  function cancelLeave($conn, $json){
    $data = json_decode($json, true);
    $leave_id = isset($data['leave_id']) ? (int)$data['leave_id'] : 0;
    if (!$leave_id) return json_encode(0);

    // Verify ownership and pending status
    $check = $conn->prepare('SELECT employee_id, status, start_date, end_date FROM tblleaves WHERE leave_id = :id LIMIT 1');
    $check->bindParam(':id', $leave_id, PDO::PARAM_INT);
    $check->execute();
    $row = $check->fetch(PDO::FETCH_ASSOC);
    if (!$row) { http_response_code(404); return json_encode(0); }
    if (strtolower($row['status']) !== 'pending') { http_response_code(403); return json_encode(0); }

    // Ensure the actor is the owner (if session has employee_id)
    if (isset($_SESSION['user_id'])) {
      $u = $conn->prepare('SELECT employee_id FROM tblusers WHERE user_id = :id LIMIT 1');
      $u->bindParam(':id', $_SESSION['user_id'], PDO::PARAM_INT);
      $u->execute();
      $urow = $u->fetch(PDO::FETCH_ASSOC);
      if ($urow && intval($urow['employee_id']) > 0 && intval($urow['employee_id']) !== intval($row['employee_id'])) {
        http_response_code(403);
        return json_encode(0);
      }
    }

    $sql = "UPDATE tblleaves
            SET status = 'rejected', rejected_by = NULL, rejected_at = NOW(),
                approved_by = NULL, approved_at = NULL
            WHERE leave_id = :id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id', $leave_id, PDO::PARAM_INT);
    $ok = $stmt->execute();

    // Notify employee and broadcast to managers and HR about the self-cancellation; also log cancellation
    try {
      if ($ok) {
        $eid = (int)$row['employee_id'];
        $actor = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
        $reason = isset($data['reason']) ? trim($data['reason']) : '';

        // 1) Log cancellation details for audit
        try {
          $insCancel = $conn->prepare('INSERT INTO tblleave_cancellations(leave_id, employee_id, cancelled_by_user_id, reason) VALUES(:lid, :eid, :actor, :reason)');
          $insCancel->bindParam(':lid', $leave_id, PDO::PARAM_INT);
          $insCancel->bindParam(':eid', $eid, PDO::PARAM_INT);
          if ($actor !== null) { $insCancel->bindParam(':actor', $actor, PDO::PARAM_INT); } else { $null = null; $insCancel->bindParam(':actor', $null, PDO::PARAM_NULL); }
          $insCancel->bindParam(':reason', $reason);
          $insCancel->execute();
        } catch (Exception $e) { /* ignore logging errors */ }

        // 2) Notify the employee
        if ($eid > 0) {
          $msg = 'You cancelled your leave request';
          if ($reason !== '') { $msg .= ' — Reason: ' . $reason; }
          $ins = $conn->prepare('INSERT INTO tblnotifications(employee_id, message, type, actor_user_id) VALUES(:eid, :msg, :type, :actor)');
          $type = 'cancelled';
          $ins->bindParam(':eid', $eid, PDO::PARAM_INT);
          $ins->bindParam(':msg', $msg);
          $ins->bindParam(':type', $type);
          if ($actor !== null) { $ins->bindParam(':actor', $actor, PDO::PARAM_INT); } else { $null = null; $ins->bindParam(':actor', $null, PDO::PARAM_NULL); }
          $ins->execute();
        }

        // 3) Broadcast to all HR and Manager users (with mapped employee_id)
        try {
          $recipients = $conn->prepare("SELECT employee_id FROM tblusers WHERE role IN ('hr','manager') AND employee_id IS NOT NULL");
          $recipients->execute();
          $rows = $recipients->fetchAll(PDO::FETCH_ASSOC);
          if ($rows) {
            // Compose a descriptive message including employee name and date range
            $empName = '';
            try {
              $einfo = $conn->prepare('SELECT first_name, last_name FROM tblemployees WHERE employee_id = :eid LIMIT 1');
              $einfo->bindParam(':eid', $eid, PDO::PARAM_INT);
              $einfo->execute();
              $erow = $einfo->fetch(PDO::FETCH_ASSOC);
              if ($erow) { $empName = trim(((isset($erow['first_name']) ? $erow['first_name'] : '') . ' ' . (isset($erow['last_name']) ? $erow['last_name'] : ''))); }
            } catch (Exception $e) { /* ignore */ }
            $dates = '';
            if (!empty($row['start_date']) && !empty($row['end_date'])) { $dates = $row['start_date'] . ' → ' . $row['end_date']; }
            $m = ($empName !== '' ? $empName : ('Employee #' . $eid)) . ' cancelled a leave request' . ($dates ? ' (' . $dates . ')' : '');
            if ($reason !== '') { $m .= ' — Reason: ' . $reason; }

            foreach ($rows as $r) {
              $rid = (int)$r['employee_id'];
              if ($rid <= 0) continue;
              $ins2 = $conn->prepare('INSERT INTO tblnotifications(employee_id, message, type, actor_user_id) VALUES(:eid, :msg, :type, :actor)');
              $ntype = 'leave_cancelled';
              $ins2->bindParam(':eid', $rid, PDO::PARAM_INT);
              $ins2->bindParam(':msg', $m);
              $ins2->bindParam(':type', $ntype);
              if ($actor !== null) { $ins2->bindParam(':actor', $actor, PDO::PARAM_INT); } else { $null = null; $ins2->bindParam(':actor', $null, PDO::PARAM_NULL); }
              $ins2->execute();
            }
          }
        } catch (Exception $e) { /* ignore broadcast errors */ }
      }
    } catch (Exception $e) { /* ignore notification errors */ }

    return json_encode($ok ? 1 : 0);
  }

  function updateLeave($conn, $json){
    $data = json_decode($json, true);
    $leave_id = isset($data['leave_id']) ? (int)$data['leave_id'] : 0;
    $start = isset($data['start_date']) ? $data['start_date'] : null;
    $end = isset($data['end_date']) ? $data['end_date'] : null;
    $reason = isset($data['reason']) ? $data['reason'] : '';
    $leaveType = isset($data['leave_type']) ? strtolower(trim($data['leave_type'])) : '';

    if (!$leave_id || !$start || !$end) { http_response_code(400); return json_encode(['success' => 0, 'message' => 'Missing parameters']); }

    // Only allow update if status is pending and (optionally) owned by employee in session
    $check = $conn->prepare('SELECT employee_id, status, leave_type FROM tblleaves WHERE leave_id = :id');
    $check->bindParam(':id', $leave_id, PDO::PARAM_INT);
    $check->execute();
    $row = $check->fetch(PDO::FETCH_ASSOC);
    if (!$row) { http_response_code(404); return json_encode(['success' => 0, 'message' => 'Leave not found']); }
    if (strtolower($row['status']) !== 'pending') { http_response_code(403); return json_encode(['success' => 0, 'message' => 'Only pending requests can be edited']); }

    if (isset($_SESSION['user_id'])) {
      $u = $conn->prepare('SELECT employee_id FROM tblusers WHERE user_id = :id LIMIT 1');
      $u->bindParam(':id', $_SESSION['user_id'], PDO::PARAM_INT);
      $u->execute();
      $urow = $u->fetch(PDO::FETCH_ASSOC);
      if ($urow && intval($urow['employee_id']) > 0 && intval($urow['employee_id']) !== intval($row['employee_id'])) {
        http_response_code(403);
        return json_encode(['success' => 0, 'message' => 'Not allowed']);
      }
    }

    $leaveType = normalizeLeaveType($conn, $leaveType, $row['leave_type']);

    // Ensure schema supports dynamic leave types (convert ENUM -> VARCHAR if needed)
    try { ensureLeaveTypeColumnsAreVarchar($conn); } catch (Exception $e) {}

    $sql = 'UPDATE tblleaves SET start_date = :start, end_date = :end, reason = :reason, leave_type = :type WHERE leave_id = :id';
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':start', $start);
    $stmt->bindParam(':end', $end);
    $stmt->bindParam(':reason', $reason);
    $stmt->bindParam(':type', $leaveType);
    $stmt->bindParam(':id', $leave_id, PDO::PARAM_INT);
    try {
      $ok = $stmt->execute();
    } catch (PDOException $e) {
      try { ensureLeaveTypeColumnsAreVarchar($conn); } catch (Exception $e2) {}
      try { $ok = $stmt->execute(); } catch (PDOException $e3) { $ok = false; }
    }

    return json_encode(['success' => $ok ? 1 : 0]);
  }

  function getAllowedLeaveTypes($conn) {
    try {
      $stmt = $conn->query("SELECT name FROM tblleave_types WHERE is_active = 1");
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
      $names = [];
      foreach ($rows as $r) { $names[] = strtolower(trim($r['name'])); }
      if (empty($names)) { $names = ['vacation','sick leave','birthday leave','deductible against pay','maternity','paternity']; }
      return $names;
    } catch (Exception $e) {
      return ['vacation','sick leave','birthday leave','deductible against pay','maternity','paternity'];
    }
  }

  function normalizeLeaveType($conn, $input, $default) {
    $val = strtolower(trim((string)$input));
    $allowed = getAllowedLeaveTypes($conn);
    if (in_array($val, $allowed, true)) return $val;
    return $default;
  }
  
  // Ensure leave_type columns accept dynamic values by converting ENUM to VARCHAR if needed
  function ensureLeaveTypeColumnsAreVarchar($conn){
    try {
      $stmt = $conn->prepare("SHOW COLUMNS FROM `tblleaves` LIKE 'leave_type'");
      $stmt->execute();
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      if ($row && isset($row['Type']) && stripos($row['Type'], 'enum(') === 0) {
        $conn->exec("ALTER TABLE `tblleaves` MODIFY `leave_type` VARCHAR(100) NOT NULL");
      }
    } catch (Exception $e) {}
    try {
      $stmt = $conn->prepare("SHOW COLUMNS FROM `tblleave_archive` LIKE 'leave_type'");
      $stmt->execute();
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      if ($row && isset($row['Type']) && stripos($row['Type'], 'enum(') === 0) {
        $conn->exec("ALTER TABLE `tblleave_archive` MODIFY `leave_type` VARCHAR(100) NOT NULL");
      }
    } catch (Exception $e) {}
  }
  /**
   * ARCHIVE LEAVE REQUESTS (BULK)
   * Inserts matching leave rows into tblleave_archive; skips duplicates
   */
  function archiveLeaveBulk($conn, $json){
    try {
      $data = json_decode($json, true);
      $ids = isset($data['leave_ids']) && is_array($data['leave_ids']) ? $data['leave_ids'] : [];
      $reason = isset($data['reason']) ? trim($data['reason']) : '';
      $archivedBy = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
      $succeeded = 0; $skipped = 0; $failed = 0;
      $sel = $conn->prepare('SELECT * FROM tblleaves WHERE leave_id = :id LIMIT 1');
      $chk = $conn->prepare('SELECT COUNT(*) FROM tblleave_archive WHERE leave_id = :id');
      $ins = $conn->prepare('INSERT INTO tblleave_archive (leave_id, employee_id, start_date, end_date, reason, leave_type, status, approved_by, approved_at, rejected_by, rejected_at, created_at, archived_reason, archived_by, archived_at) VALUES (:leave_id, :employee_id, :start_date, :end_date, :reason, :leave_type, :status, :approved_by, :approved_at, :rejected_by, :rejected_at, :created_at, :archived_reason, :archived_by, NOW())');
      foreach ($ids as $rawId){
        $id = (int)$rawId; if ($id <= 0) { $failed++; continue; }
        try {
          $sel->bindParam(':id', $id, PDO::PARAM_INT);
          $sel->execute();
          $row = $sel->fetch(PDO::FETCH_ASSOC);
          if (!$row) { $failed++; continue; }
          $chk->bindParam(':id', $id, PDO::PARAM_INT);
          $chk->execute();
          $exists = ((int)$chk->fetchColumn()) > 0;
          if ($exists) { $skipped++; continue; }
          $ins->bindValue(':leave_id', $id, PDO::PARAM_INT);
          $ins->bindValue(':employee_id', (int)$row['employee_id'], PDO::PARAM_INT);
          $ins->bindValue(':start_date', $row['start_date']);
          $ins->bindValue(':end_date', $row['end_date']);
          $ins->bindValue(':reason', $row['reason']);
          $ins->bindValue(':leave_type', $row['leave_type']);
          $ins->bindValue(':status', $row['status']);
          if (!empty($row['approved_by'])) { $ins->bindValue(':approved_by', (int)$row['approved_by'], PDO::PARAM_INT); } else { $ins->bindValue(':approved_by', null, PDO::PARAM_NULL); }
          if (!empty($row['approved_at'])) { $ins->bindValue(':approved_at', $row['approved_at']); } else { $ins->bindValue(':approved_at', null, PDO::PARAM_NULL); }
          if (!empty($row['rejected_by'])) { $ins->bindValue(':rejected_by', (int)$row['rejected_by'], PDO::PARAM_INT); } else { $ins->bindValue(':rejected_by', null, PDO::PARAM_NULL); }
          if (!empty($row['rejected_at'])) { $ins->bindValue(':rejected_at', $row['rejected_at']); } else { $ins->bindValue(':rejected_at', null, PDO::PARAM_NULL); }
          if (!empty($row['created_at'])) { $ins->bindValue(':created_at', $row['created_at']); } else { $ins->bindValue(':created_at', null, PDO::PARAM_NULL); }
          if ($reason !== '') { $ins->bindValue(':archived_reason', $reason, PDO::PARAM_STR); } else { $ins->bindValue(':archived_reason', null, PDO::PARAM_NULL); }
          if ($archivedBy) { $ins->bindValue(':archived_by', $archivedBy, PDO::PARAM_INT); } else { $ins->bindValue(':archived_by', null, PDO::PARAM_NULL); }
          try {
            $ok = $ins->execute();
          } catch (PDOException $e) {
            try { ensureLeaveTypeColumnsAreVarchar($conn); } catch (Exception $e2) {}
            try { $ok = $ins->execute(); } catch (PDOException $e3) { $ok = false; }
          }
          if ($ok) $succeeded++; else $failed++;
        } catch (Exception $e) {
          $failed++;
        }
      }
      return json_encode(['succeeded' => $succeeded, 'skipped' => $skipped, 'failed' => $failed]);
    } catch (Exception $e) {
      return json_encode(['succeeded' => 0, 'skipped' => 0, 'failed' => 0, 'message' => 'Archive error: ' . $e->getMessage()]);
    }
  }

  /**
   * LIST ARCHIVED LEAVES
   */
  function listLeaveArchive($conn){
    try {
      $sql = "SELECT a.*, e.first_name, e.last_name, e.department FROM tblleave_archive a INNER JOIN tblemployees e ON e.employee_id = a.employee_id ORDER BY a.archived_at DESC, a.archive_id DESC";
      $stmt = $conn->prepare($sql);
      $stmt->execute();
      return json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    } catch (Exception $e) { return json_encode([]); }
  }

  /**
   * UNARCHIVE ALL (CLEAR ARCHIVE TABLE)
   */
  function unarchiveAllLeaves($conn){
    try {
      $stmt = $conn->prepare('DELETE FROM tblleave_archive');
      $ok = $stmt->execute();
      return json_encode(['success' => $ok ? 1 : 0]);
    } catch (Exception $e) { return json_encode(['success' => 0]); }
  }
?>


