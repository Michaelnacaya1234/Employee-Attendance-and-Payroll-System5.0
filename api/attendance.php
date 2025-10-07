<?php
  header('Content-Type: application/json');
  header('Access-Control-Allow-Origin: *');

  if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    exit(0);
  }

  include 'connection-pdo.php';

  $operation = '';
  if ($_SERVER['REQUEST_METHOD'] == 'GET'){
    $operation = isset($_GET['operation']) ? $_GET['operation'] : '';
  } else if($_SERVER['REQUEST_METHOD'] == 'POST'){
    $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
  }

  switch ($operation) {
    case 'getAttendance':
      echo getAttendance($conn);
      break;
    case 'recordAttendance':
      echo recordAttendance($conn);
      break;
    case 'updateAttendance':
      echo updateAttendance($conn);
      break;
    case 'deleteAttendance':
      echo deleteAttendance($conn);
      break;
    case 'recentActivities':
      echo recentActivities($conn);
      break;
    default:
      echo json_encode([]);
  }

  /**
   * RETRIEVE ATTENDANCE RECORDS WITH EMPLOYEE DETAILS
   * Fetches attendance data joined with employee information
   * Supports optional date range filtering
   */
  function getAttendance($conn){
    $sql = "SELECT a.*, e.first_name, e.last_name, e.department, e.position
            FROM tblattendance a
            INNER JOIN tblemployees e ON e.employee_id = a.employee_id
            WHERE 1=1";
    $params = [];
    if (!empty($_GET['start_date'])) {
      $sql .= " AND a.attendance_date >= :start_date";
      $params[':start_date'] = $_GET['start_date'];
    }
    if (!empty($_GET['end_date'])) {
      $sql .= " AND a.attendance_date <= :end_date";
      $params[':end_date'] = $_GET['end_date'];
    }
    $sql .= " ORDER BY a.attendance_date DESC, a.attendance_id DESC";

    $stmt = $conn->prepare($sql);
    foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return json_encode($rows);
  }

  /**
   * VALIDATE EMPLOYEE LEAVE STATUS
   * Checks if employee has approved leave on specified date
   * Prevents attendance recording during leave periods
   */
  function hasApprovedLeaveOn($conn, $employee_id, $date){
    try {
      $sql = "SELECT 1 FROM tblleaves WHERE employee_id = :eid AND status = 'approved' AND start_date <= :d AND end_date >= :d LIMIT 1";
      $stmt = $conn->prepare($sql);
      $stmt->bindParam(':eid', $employee_id, PDO::PARAM_INT);
      $stmt->bindParam(':d', $date);
      $stmt->execute();
      return $stmt->fetch(PDO::FETCH_ASSOC) ? true : false;
    } catch (Exception $e) { return false; }
  }

  /**
   * CREATE NEW ATTENDANCE RECORD
   * Inserts attendance entry with duplicate prevention
   * Validates against approved leave status
   */
  function recordAttendance($conn){
    $data = json_decode($_POST['json'], true);
    $eid = isset($data['employee_id']) ? (int)$data['employee_id'] : 0;
    $d = isset($data['attendance_date']) ? $data['attendance_date'] : '';
    if ($eid > 0 && $d !== '' && hasApprovedLeaveOn($conn, $eid, $d)){
      http_response_code(409);
      return json_encode(['success' => 0, 'message' => 'Cannot record attendance while on approved leave.']);
    }
    // prevent duplicate per employee/date using INSERT IGNORE with unique index
    $sql = "INSERT IGNORE INTO tblattendance(employee_id, attendance_date, time_in, time_out, status, remarks)
            VALUES(:employee_id, :attendance_date, :time_in, :time_out, :status, :remarks)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':employee_id', $data['employee_id']);
    $stmt->bindParam(':attendance_date', $data['attendance_date']);
    $stmt->bindParam(':time_in', $data['time_in']);
    $stmt->bindParam(':time_out', $data['time_out']);
    $stmt->bindParam(':status', $data['status']);
    $stmt->bindParam(':remarks', $data['remarks']);
    $stmt->execute();
    try { syncDailyAttendance($conn, (int)$data['employee_id'], $data['attendance_date']); } catch (Exception $e) {}
    return json_encode($stmt->rowCount() > 0 ? 1 : 0);
  }

  /**
   * UPDATE EXISTING ATTENDANCE RECORD
   * Modifies attendance entry with leave validation
   * Maintains data integrity with sync operations
   */
  function updateAttendance($conn){
    $data = json_decode($_POST['json'], true);
    $eid = isset($data['employee_id']) ? (int)$data['employee_id'] : 0;
    $d = isset($data['attendance_date']) ? $data['attendance_date'] : '';
    if ($eid > 0 && $d !== '' && hasApprovedLeaveOn($conn, $eid, $d)){
      http_response_code(409);
      return json_encode(['success' => 0, 'message' => 'Cannot update attendance while on approved leave.']);
    }
    $sql = "UPDATE tblattendance SET
              employee_id = :employee_id,
              attendance_date = :attendance_date,
              time_in = :time_in,
              time_out = :time_out,
              status = :status,
              remarks = :remarks
            WHERE attendance_id = :attendance_id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':attendance_id', $data['attendance_id']);
    $stmt->bindParam(':employee_id', $data['employee_id']);
    $stmt->bindParam(':attendance_date', $data['attendance_date']);
    $stmt->bindParam(':time_in', $data['time_in']);
    $stmt->bindParam(':time_out', $data['time_out']);
    $stmt->bindParam(':status', $data['status']);
    $stmt->bindParam(':remarks', $data['remarks']);
    $stmt->execute();
    try { syncDailyAttendance($conn, (int)$data['employee_id'], $data['attendance_date']); } catch (Exception $e) {}
    return json_encode($stmt->rowCount() > 0 ? 1 : 0);
  }

  /**
   * GET RECENT ATTENDANCE ACTIVITIES
   * Retrieves latest attendance records for dashboard
   * Supports configurable result limit
   */
  function recentActivities($conn){
    $limit = isset($_GET['limit']) ? intval($_GET['limit']) : 10;
    if ($limit <= 0 || $limit > 100) $limit = 10;
    $sql = "SELECT a.attendance_id, a.attendance_date, a.time_in, a.time_out, a.status,
                   e.employee_id, e.first_name, e.last_name, e.department
            FROM tblattendance a
            INNER JOIN tblemployees e ON e.employee_id = a.employee_id
            ORDER BY a.attendance_date DESC, a.attendance_id DESC
            LIMIT :lim";
    $stmt = $conn->prepare($sql);
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return json_encode($rows);
  }

  /**
   * DELETE ATTENDANCE RECORD
   * Removes attendance entry and syncs daily summaries
   * Captures data before deletion for proper cleanup
   */
  function deleteAttendance($conn){
    $data = json_decode($_POST['json'], true);

    // Get employee and date before deletion for syncing daily tables
    $sel = $conn->prepare("SELECT employee_id, attendance_date FROM tblattendance WHERE attendance_id = :id LIMIT 1");
    $sel->bindParam(':id', $data['attendance_id']);
    $sel->execute();
    $row = $sel->fetch(PDO::FETCH_ASSOC);
    $eid = $row ? intval($row['employee_id']) : 0;
    $d = $row ? $row['attendance_date'] : null;

    $sql = "DELETE FROM tblattendance WHERE attendance_id = :attendance_id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':attendance_id', $data['attendance_id']);
    $stmt->execute();

    if ($eid && $d) { try { syncDailyAttendance($conn, $eid, $d); } catch (Exception $e) {} }

    return json_encode($stmt->rowCount() > 0 ? 1 : 0);
  }

  /**
   * SYNCHRONIZE DAILY ATTENDANCE SUMMARIES
   * Maintains consistency between attendance and summary tables
   * Updates both employee daily records and system totals
   */
  function syncDailyAttendance($conn, $employee_id, $date){
    try {
      // Find attendance row for employee/date
      $sql = "SELECT status, time_in, time_out FROM tblattendance WHERE employee_id = :eid AND attendance_date = :d LIMIT 1";
      $stmt = $conn->prepare($sql);
      $stmt->bindParam(':eid', $employee_id, PDO::PARAM_INT);
      $stmt->bindParam(':d', $date);
      $stmt->execute();
      $row = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($row) {
        $status = (isset($row['status']) && $row['status'] !== null && $row['status'] !== '') ? $row['status'] : 'present';
        // Upsert employee daily
        $ins = "INSERT INTO tblattendance_employee_daily (employee_id, attendance_date, status)
                VALUES (:eid, :d, :st)
                ON DUPLICATE KEY UPDATE status = VALUES(status)";
        $insStmt = $conn->prepare($ins);
        $insStmt->bindParam(':eid', $employee_id, PDO::PARAM_INT);
        $insStmt->bindParam(':d', $date);
        $insStmt->bindParam(':st', $status);
        $insStmt->execute();
      } else {
        // No attendance row -> remove any daily record
        $del = "DELETE FROM tblattendance_employee_daily WHERE employee_id = :eid AND attendance_date = :d";
        $delStmt = $conn->prepare($del);
        $delStmt->bindParam(':eid', $employee_id, PDO::PARAM_INT);
        $delStmt->bindParam(':d', $date);
        $delStmt->execute();
      }

      // Recompute summary aggregates for the date
      $cntSql = "SELECT
                   SUM(status = 'present') AS total_present,
                   SUM(status = 'absent') AS total_absent,
                   SUM(status = 'late') AS total_late,
                   SUM(status = 'leave') AS total_leave,
                   SUM(status = 'undertime') AS total_undertime,
                   COUNT(*) AS total_rows
                 FROM tblattendance_employee_daily
                 WHERE attendance_date = :d";
      $c = $conn->prepare($cntSql);
      $c->bindParam(':d', $date);
      $c->execute();
      $cRow = $c->fetch(PDO::FETCH_ASSOC);

      $totalRows = intval($cRow['total_rows'] ?? 0);
      if ($totalRows > 0) {
        $up = "INSERT INTO tblattendance_daily_summary
                 (summary_date, total_present, total_absent, total_late, total_leave, total_undertime)
               VALUES
                 (:d, :p, :a, :l, :lv, :u)
               ON DUPLICATE KEY UPDATE
                 total_present = VALUES(total_present),
                 total_absent = VALUES(total_absent),
                 total_late = VALUES(total_late),
                 total_leave = VALUES(total_leave),
                 total_undertime = VALUES(total_undertime)";
        $upStmt = $conn->prepare($up);
        $upStmt->bindParam(':d', $date);
        $upStmt->bindValue(':p', intval($cRow['total_present'] ?? 0), PDO::PARAM_INT);
        $upStmt->bindValue(':a', intval($cRow['total_absent'] ?? 0), PDO::PARAM_INT);
        $upStmt->bindValue(':l', intval($cRow['total_late'] ?? 0), PDO::PARAM_INT);
        $upStmt->bindValue(':lv', intval($cRow['total_leave'] ?? 0), PDO::PARAM_INT);
        $upStmt->bindValue(':u', intval($cRow['total_undertime'] ?? 0), PDO::PARAM_INT);
        $upStmt->execute();
      } else {
        // No per-employee records for the date -> remove summary row if exists
        $del2 = "DELETE FROM tblattendance_daily_summary WHERE summary_date = :d";
        $del2Stmt = $conn->prepare($del2);
        $del2Stmt->bindParam(':d', $date);
        $del2Stmt->execute();
      }
    } catch (Exception $e) {
      // Do not interrupt primary flow on sync errors
    }
  }
?>


