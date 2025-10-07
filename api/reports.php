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

  $operation = isset($_GET['operation']) ? $_GET['operation'] : '';
  switch ($operation) {
    case 'attendanceSummary':
      echo attendanceSummary($conn);
      break;
    case 'payrollSummary':
      echo payrollSummary($conn);
      break;
    case 'dashboardSummary':
      echo dashboardSummary($conn);
      break;
    case 'attendanceOverview':
      echo attendanceOverview($conn);
      break;
    case 'payrollTrend':
      echo payrollTrend($conn);
      break;
    case 'overtimeDistribution':
      echo overtimeDistribution($conn);
      break;
    case 'leaveTypeDistribution':
      echo leaveTypeDistribution($conn);
      break;
    case 'deductionsBreakdown':
      echo deductionsBreakdown($conn);
      break;
    case 'employeeCountTrend':
      echo employeeCountTrend($conn);
      break;
    case 'absenceByDepartment':
      echo absenceByDepartment($conn);
      break;
    case 'getAuditLogs':
      echo getAuditLogs($conn);
      break;
    // New report module operations
    case 'generateReport':
      echo generateReport($conn);
      break;
    case 'listReports':
      echo listReports($conn);
      break;
    case 'downloadReport':
      downloadReport($conn); // will set headers and exit
      break;
    case 'exportReports':
      exportReports($conn); // will set headers and exit
      break;
    default:
      echo json_encode([]);
  }

  /**
   * GENERATE ATTENDANCE SUMMARY REPORT
   * Aggregates attendance data by status within date range
   * Returns counts for present, absent, and leave statuses
   */
  function attendanceSummary($conn){
    $sql = "SELECT status, COUNT(*) as cnt FROM tblattendance WHERE 1=1";
    $params = [];
    if (!empty($_GET['start_date'])) { $sql .= " AND attendance_date >= :start"; $params[':start'] = $_GET['start_date']; }
    if (!empty($_GET['end_date'])) { $sql .= " AND attendance_date <= :end"; $params[':end'] = $_GET['end_date']; }
    $sql .= " GROUP BY status";
    $stmt = $conn->prepare($sql);
    foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $out = ['present' => 0, 'absent' => 0, 'leave' => 0];
    foreach ($rows as $r) { $out[$r['status']] = intval($r['cnt']); }
    return json_encode($out);
  }

  /**
   * GENERATE PAYROLL SUMMARY REPORT
   * Calculates total net pay, deductions, and overtime for paid payrolls
   * Excludes archived payroll records from calculations
   */
  function payrollSummary($conn){
    $sql = "SELECT COALESCE(SUM(p.net_pay),0) total_net_pay,
                   COALESCE(SUM(p.deductions),0) total_deductions,
                   COALESCE(SUM(p.overtime_pay),0) total_overtime_pay
            FROM tblpayroll p
            LEFT JOIN tblpayroll_archive a ON a.payroll_id = p.payroll_id
            WHERE p.status='paid' AND a.payroll_id IS NULL";
    $params = [];
    if (!empty($_GET['start_date'])) { $sql .= " AND payroll_period_start >= :start"; $params[':start'] = $_GET['start_date']; }
    if (!empty($_GET['end_date'])) { $sql .= " AND payroll_period_end <= :end"; $params[':end'] = $_GET['end_date']; }
    $stmt = $conn->prepare($sql);
    foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return json_encode($row ?: ['total_net_pay' => 0, 'total_deductions' => 0, 'total_overtime_pay' => 0]);
  }

  /**
   * GENERATE DASHBOARD SUMMARY DATA
   * Compiles key metrics for dashboard display
   * Includes employee counts, attendance, leaves, and upcoming events
   */
  function dashboardSummary($conn){
    // total employees
    $total = (int)$conn->query("SELECT COUNT(*) FROM tblemployees")->fetchColumn();
    $presentToday = (int)$conn->query("SELECT COUNT(*) FROM tblattendance WHERE attendance_date = CURDATE() AND status='present'")->fetchColumn();
    $pendingLeaves = (int)$conn->query("SELECT COUNT(*) FROM tblleaves WHERE status='pending'")->fetchColumn();
    $processedPayrolls = (int)$conn->query("SELECT COUNT(*) FROM tblpayroll p LEFT JOIN tblpayroll_archive a ON a.payroll_id = p.payroll_id WHERE MONTH(p.payroll_period_end)=MONTH(CURDATE()) AND YEAR(p.payroll_period_end)=YEAR(CURDATE()) AND p.status='paid' AND a.payroll_id IS NULL")->fetchColumn();

    // Upcoming birthdays (next 30 days)
    $birthdays = $conn->query("SELECT employee_id, first_name, last_name, DATE_FORMAT(date_of_birth, '%m-%d') md FROM tblemployees WHERE date_of_birth IS NOT NULL")->fetchAll(PDO::FETCH_ASSOC);
    $upcoming_birthdays = [];
    $todayMd = date('m-d');
    $window = new DateTime('+30 days');
    foreach ($birthdays as $b) {
      $year = date('Y');
      $dateThisYear = DateTime::createFromFormat('Y-m-d', $year . '-' . $b['md']);
      if (!$dateThisYear) { continue; }
      $now = new DateTime('today');
      if ($dateThisYear < $now) { $dateThisYear->modify('+1 year'); }
      $diff = $now->diff($dateThisYear)->days;
      if ($diff <= 30) {
        $upcoming_birthdays[] = [
          'employee_id' => $b['employee_id'],
          'name' => $b['first_name'] . ' ' . $b['last_name'],
          'date' => $dateThisYear->format('Y-m-d')
        ];
      }
    }

    // Upcoming work anniversaries (next 30 days)
    $annivRows = $conn->query("SELECT employee_id, first_name, last_name, DATE_FORMAT(date_hired, '%m-%d') md FROM tblemployees WHERE date_hired IS NOT NULL")->fetchAll(PDO::FETCH_ASSOC);
    $upcoming_anniversaries = [];
    foreach ($annivRows as $a) {
      $year = date('Y');
      $dateThisYear = DateTime::createFromFormat('Y-m-d', $year . '-' . $a['md']);
      if (!$dateThisYear) { continue; }
      $now = new DateTime('today');
      if ($dateThisYear < $now) { $dateThisYear->modify('+1 year'); }
      $diff = $now->diff($dateThisYear)->days;
      if ($diff <= 30) {
        $upcoming_anniversaries[] = [
          'employee_id' => $a['employee_id'],
          'name' => $a['first_name'] . ' ' . $a['last_name'],
          'date' => $dateThisYear->format('Y-m-d')
        ];
      }
    }

    return json_encode([
      'total_employees' => $total,
      'present_today' => $presentToday,
      'pending_leaves' => $pendingLeaves,
      'payrolls_processed_this_month' => $processedPayrolls,
      'upcoming_birthdays' => $upcoming_birthdays,
      'upcoming_anniversaries' => $upcoming_anniversaries,
    ]);
  }

  /**
   * GENERATE ATTENDANCE OVERVIEW CHART DATA
   * Provides attendance trends by day for week or month periods
   * Returns data formatted for chart visualization
   */
  function attendanceOverview($conn) {
    $period = isset($_GET['period']) ? $_GET['period'] : 'week';

    if ($period === 'week') {
      $sql = "SELECT
                DATE(attendance_date) as date,
                SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present,
                SUM(CASE WHEN status = 'late' THEN 1 ELSE 0 END) as late,
                SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent,
                SUM(CASE WHEN status = 'leave' THEN 1 ELSE 0 END) as onLeave
              FROM tblattendance
              WHERE attendance_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
              GROUP BY DATE(attendance_date)
              ORDER BY date";
    } else {
      $sql = "SELECT
                DATE(attendance_date) as date,
                SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present,
                SUM(CASE WHEN status = 'late' THEN 1 ELSE 0 END) as late,
                SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent,
                SUM(CASE WHEN status = 'leave' THEN 1 ELSE 0 END) as onLeave
              FROM tblattendance
              WHERE attendance_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
              GROUP BY DATE(attendance_date)
              ORDER BY date";
    }

    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $labels = [];
    $present = [];
    $late = [];
    $absent = [];
    $onLeave = [];

    foreach ($rows as $row) {
      $labels[] = date('D', strtotime($row['date']));
      $present[] = (int)$row['present'];
      $late[] = (int)$row['late'];
      $absent[] = (int)$row['absent'];
      $onLeave[] = (int)$row['onLeave'];
    }

    return json_encode([
      'labels' => $labels,
      'present' => $present,
      'late' => $late,
      'absent' => $absent,
      'onLeave' => $onLeave
    ]);
  }

  function payrollTrend($conn) {
    $months = isset($_GET['months']) ? (int)$_GET['months'] : 6;

    $sql = "SELECT
              DATE_FORMAT(payroll_period_end, '%Y-%m') as month,
              SUM(net_pay + deductions) as total_expense
            FROM tblpayroll
            WHERE payroll_period_end >= DATE_SUB(CURDATE(), INTERVAL ? MONTH)
            GROUP BY DATE_FORMAT(payroll_period_end, '%Y-%m')
            ORDER BY month";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $months, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $labels = [];
    $expenses = [];

    foreach ($rows as $row) {
      $labels[] = date('M', strtotime($row['month'] . '-01'));
      $expenses[] = (float)$row['total_expense'];
    }

    return json_encode([
      'labels' => $labels,
      'expenses' => $expenses
    ]);
  }

  function overtimeDistribution($conn) {
    $sql = "SELECT
              e.department,
              COALESCE(SUM(p.total_overtime_hours), 0) as total_overtime
            FROM tblemployees e
            LEFT JOIN tblpayroll p ON e.employee_id = p.employee_id
            WHERE e.department IS NOT NULL
            GROUP BY e.department
            HAVING total_overtime > 0
            ORDER BY total_overtime DESC
            LIMIT 10";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $labels = [];
    $hours = [];
    foreach ($rows as $row) {
      $labels[] = $row['department'] ?: 'Unknown';
      $hours[] = (float)$row['total_overtime'];
    }
    return json_encode([
      'labels' => $labels,
      'hours' => $hours
    ]);
  }

  function leaveTypeDistribution($conn) {
    $sql = "SELECT
              leave_type,
              COUNT(*) as count
            FROM tblleaves
            WHERE status != 'rejected'
            GROUP BY leave_type
            ORDER BY count DESC";

    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $labels = [];
    $counts = [];

    foreach ($rows as $row) {
      $labels[] = ucfirst($row['leave_type'] ?: 'Other');
      $counts[] = (int)$row['count'];
    }

    return json_encode([
      'labels' => $labels,
      'counts' => $counts
    ]);
  }

  function computeDeductionsBreakdownForAmount($gross){
    $gross = max(0.0, floatval($gross));
    $sss = round($gross * 0.095 / 2, 2);
    $phBase = min(100000.0, max(10000.0, $gross));
    $philhealth = round($phBase * 0.05 / 2, 2);
    $pagibig = round($gross * 0.02, 2); if ($pagibig > 100.0) $pagibig = 100.0;
    $tax = computeWithholdingTaxLocal($gross);
    $total = round($sss + $philhealth + $pagibig + $tax, 2);
    return [ 'sss' => $sss, 'philhealth' => $philhealth, 'pagibig' => $pagibig, 'tax' => $tax, 'total' => $total ];
  }

  function computeWithholdingTaxLocal($monthly){
    $m = max(0.0, floatval($monthly));
    if ($m <= 20833.0) return 0.0;
    if ($m <= 33333.0) return round(($m - 20833.0) * 0.20, 2);
    if ($m <= 66667.0) return round(2500.0 + ($m - 33333.0) * 0.25, 2);
    if ($m <= 166667.0) return round(10833.33 + ($m - 66667.0) * 0.30, 2);
    if ($m <= 666667.0) return round(40833.33 + ($m - 166667.0) * 0.32, 2);
    return round(200833.33 + ($m - 666667.0) * 0.35, 2);
  }

  function deductionsBreakdown($conn) {
    // Compute totals by iterating payroll rows and applying the same rules used in payroll generation
    $stmt = $conn->prepare("SELECT payroll_id, employee_id, basic_salary, overtime_pay, net_pay, deductions FROM tblpayroll");
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $totals = [ 'SSS' => 0.0, 'PhilHealth' => 0.0, 'Pag-IBIG' => 0.0, 'Withholding Tax' => 0.0, 'Other' => 0.0 ];

    foreach ($rows as $r) {
      $basic = isset($r['basic_salary']) ? (float)$r['basic_salary'] : 0.0;
      $ot = isset($r['overtime_pay']) ? (float)$r['overtime_pay'] : 0.0;
      $gross = $basic + $ot; // no allowances or bonuses

      // Calculate individual deduction components
      $bk = computeDeductionsBreakdownForAmount($gross);
      $totals['SSS'] += $bk['sss'];
      $totals['PhilHealth'] += $bk['philhealth'];
      $totals['Pag-IBIG'] += $bk['pagibig'];
      $totals['Withholding Tax'] += $bk['tax'];

      // Calculate other deductions (difference between stored total and computed components)
      $storedDeductions = isset($r['deductions']) ? (float)$r['deductions'] : 0.0;
      $computedTotal = (float)$bk['total'];
      $other = max(0.0, round($storedDeductions - $computedTotal, 2));
      $totals['Other'] += $other;
    }

    // Round all totals to 2 decimal places for proper display
    foreach ($totals as $key => $value) {
      $totals[$key] = round($value, 2);
    }

    $labels = array_keys($totals);
    $amounts = array_values($totals);
    return json_encode([ 'labels' => $labels, 'amounts' => $amounts ]);
  }

  function employeeCountTrend($conn) {
    $months = isset($_GET['months']) ? (int)$_GET['months'] : 12;

    $sql = "SELECT
              DATE_FORMAT(date_hired, '%Y-%m') as month,
              COUNT(*) as new_employees
            FROM tblemployees
            WHERE date_hired >= DATE_SUB(CURDATE(), INTERVAL ? MONTH)
            GROUP BY DATE_FORMAT(date_hired, '%Y-%m')
            ORDER BY month";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $months, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $labels = [];
    $counts = [];
    $runningTotal = 0;

    // Generate month labels for the last N months
    for ($i = $months - 1; $i >= 0; $i--) {
      $date = date('Y-m', strtotime("-$i months"));
      $labels[] = date('M', strtotime($date . '-01'));

      // Find count for this month
      $monthCount = 0;
      foreach ($rows as $row) {
        if ($row['month'] === $date) {
          $monthCount = (int)$row['new_employees'];
          break;
        }
      }

      $runningTotal += $monthCount;
      $counts[] = $runningTotal;
    }

    return json_encode([
      'labels' => $labels,
      'counts' => $counts
    ]);
  }

  function absenceByDepartment($conn) {
    $days = isset($_GET['days']) ? intval($_GET['days']) : 30;
    if ($days <= 0) { $days = 30; }
    $sql = "SELECT e.department, COUNT(*) AS absent_count
            FROM tblattendance a
            INNER JOIN tblemployees e ON e.employee_id = a.employee_id
            WHERE a.status = 'absent'
              AND a.attendance_date >= DATE_SUB(CURDATE(), INTERVAL :days DAY)
              AND e.department IS NOT NULL AND e.department <> ''
            GROUP BY e.department
            ORDER BY absent_count DESC";
    $stmt = $conn->prepare($sql);
    $stmt->bindValue(':days', $days, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $labels = [];
    $counts = [];
    foreach ($rows as $row) {
      $labels[] = $row['department'];
      $counts[] = (int)$row['absent_count'];
    }
    return json_encode(['labels' => $labels, 'counts' => $counts]);
  }

  function getAuditLogs($conn) {
    // Get pagination parameters
    $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
    $limit = isset($_GET['limit']) ? max(1, min(100, intval($_GET['limit']))) : 10;
    $offset = ($page - 1) * $limit;

    // Get filter parameters
    $user_id = isset($_GET['user_id']) ? intval($_GET['user_id']) : null;
    $action = isset($_GET['action']) ? $_GET['action'] : null;
    $search = isset($_GET['search']) ? $_GET['search'] : null;
    $start_date = isset($_GET['start_date']) ? $_GET['start_date'] : null;
    $end_date = isset($_GET['end_date']) ? $_GET['end_date'] : null;

    // Build query
    $sql = "SELECT al.log_id, al.user_id, al.action, al.details, al.ip_address, al.created_at, u.username, u.role, e.first_name, e.last_name
            FROM tblaudit_logs al
            LEFT JOIN tblusers u ON al.user_id = u.user_id
            LEFT JOIN tblemployees e ON u.employee_id = e.employee_id
            WHERE 1=1";

    $params = [];

    if ($user_id) {
      $sql .= " AND al.user_id = :user_id";
      $params[':user_id'] = $user_id;
    }

    if ($action) {
      $sql .= " AND al.action = :action";
      $params[':action'] = $action;
    }

    if ($search) {
      $sql .= " AND (u.username LIKE :search OR al.action LIKE :search OR al.details LIKE :search)";
      $params[':search'] = "%{$search}%";
    }

    if ($start_date) {
      $sql .= " AND al.created_at >= :start_date";
      $params[':start_date'] = $start_date;
    }

    if ($end_date) {
      $sql .= " AND al.created_at <= :end_date";
      $params[':end_date'] = $end_date;
    }

    // Get total count for pagination
    $countSql = "SELECT COUNT(*) FROM tblaudit_logs al LEFT JOIN tblusers u ON al.user_id = u.user_id WHERE 1=1";
    $countParams = [];

    if ($user_id) {
      $countSql .= " AND al.user_id = :user_id";
      $countParams[':user_id'] = $user_id;
    }

    if ($action) {
      $countSql .= " AND al.action = :action";
      $countParams[':action'] = $action;
    }

    if ($search) {
      $countSql .= " AND (u.username LIKE :search OR al.action LIKE :search OR al.details LIKE :search)";
      $countParams[':search'] = "%{$search}%";
    }

    if ($start_date) {
      $countSql .= " AND al.created_at >= :start_date";
      $countParams[':start_date'] = $start_date;
    }

    if ($end_date) {
      $countSql .= " AND al.created_at <= :end_date";
      $countParams[':end_date'] = $end_date;
    }

    $countStmt = $conn->prepare($countSql);
    foreach ($countParams as $k => $v) {
      $countStmt->bindValue($k, $v);
    }
    $countStmt->execute();
    $total = $countStmt->fetchColumn();

    // Add ordering and limit
    $sql .= " ORDER BY al.created_at DESC LIMIT :limit OFFSET :offset";
    $params[':limit'] = $limit;
    $params[':offset'] = $offset;

    $stmt = $conn->prepare($sql);
    foreach ($params as $k => $v) {
      $stmt->bindValue($k, $v);
    }
    // Bind limit and offset as integers
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Format the response
    $formattedLogs = [];
    foreach ($logs as $log) {
      $formattedLogs[] = [
        'log_id' => (int)$log['log_id'],
        'user_id' => $log['user_id'] ? (int)$log['user_id'] : null,
        'username' => $log['username'] ?: 'Unknown',
        'role' => $log['role'] ?: 'Unknown',
        'full_name' => ($log['first_name'] || $log['last_name']) ? trim($log['first_name'] . ' ' . $log['last_name']) : null,
        'action' => $log['action'],
        'details' => $log['details'],
        'ip_address' => $log['ip_address'],
        'created_at' => $log['created_at']
      ];
    }

    return json_encode([
      'logs' => $formattedLogs,
      'total' => (int)$total,
      'page' => $page,
      'limit' => $limit,
      'pages' => ceil($total / $limit)
    ]);
  }
// ===== Helper: current user context and RBAC =====
function currentUser($conn){
  $u = [ 'user_id' => null, 'role' => 'guest', 'employee_id' => null, 'username' => null ];
  try {
    if (!isset($_SESSION['user_id'])) return $u;
    $uid = (int)$_SESSION['user_id'];
    if ($uid <= 0) return $u;
    $stmt = $conn->prepare("SELECT u.user_id, u.username, u.role, u.employee_id FROM tblusers u WHERE u.user_id = :uid LIMIT 1");
    $stmt->bindValue(':uid', $uid, PDO::PARAM_INT);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row){
      $u['user_id'] = (int)$row['user_id'];
      $u['username'] = $row['username'];
      $u['role'] = $row['role'];
      $u['employee_id'] = $row['employee_id'] ? (int)$row['employee_id'] : null;
    }
  } catch (Exception $e) {}
  return $u;
}
function canSeeAll($me){ return in_array(strtolower($me['role']), ['admin','hr']); }

// ===== New: Generate reports (insert into report tables) =====
function generateReport($conn){
  $type = isset($_REQUEST['type']) ? strtolower(trim($_REQUEST['type'])) : '';
  $payload = [];
  if (isset($_POST['json'])) { $payload = json_decode($_POST['json'], true) ?: []; }
  $me = currentUser($conn);
  $uid = $me['user_id'] ?: null;

  $start = isset($payload['start_date']) ? $payload['start_date'] : (isset($_GET['start_date']) ? $_GET['start_date'] : null);
  $end = isset($payload['end_date']) ? $payload['end_date'] : (isset($_GET['end_date']) ? $_GET['end_date'] : null);
  $employee_id = isset($payload['employee_id']) ? (int)$payload['employee_id'] : (isset($_GET['employee_id']) ? (int)$_GET['employee_id'] : 0);
  $department_id = isset($payload['department_id']) ? (int)$payload['department_id'] : (isset($_GET['department_id']) ? (int)$_GET['department_id'] : 0);

  try {
    if ($type === 'payroll') {
      // Generate payroll reports for payroll rows in range (or all if none provided)
      $sql = "SELECT p.*, e.first_name, e.last_name FROM tblpayroll p INNER JOIN tblemployees e ON e.employee_id=p.employee_id WHERE 1=1";
      $params = [];
      if ($start) { $sql .= " AND p.payroll_period_start >= :start"; $params[':start'] = $start; }
      if ($end) { $sql .= " AND p.payroll_period_end <= :end"; $params[':end'] = $end; }
      if ($employee_id) { $sql .= " AND p.employee_id = :emp"; $params[':emp'] = $employee_id; }
      // RBAC scope
      if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND p.employee_id = :me_emp"; $params[':me_emp'] = $me['employee_id']; }
      $stmt = $conn->prepare($sql);
      foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

      $ins = $conn->prepare("INSERT INTO tblPayrollReports (Payroll_ID, Employee_ID, Period_Start, Period_End, Basic_Salary, Total_Deductions, Net_Pay, Generated_By) VALUES (:pid, :eid, :ps, :pe, :basic, :ded, :net, :gen)");
      $count = 0;
      foreach ($rows as $r){
        $ins->bindValue(':pid', (int)$r['payroll_id'], PDO::PARAM_INT);
        $ins->bindValue(':eid', (int)$r['employee_id'], PDO::PARAM_INT);
        $ins->bindValue(':ps', $r['payroll_period_start']);
        $ins->bindValue(':pe', $r['payroll_period_end']);
        $ins->bindValue(':basic', $r['basic_salary']);
                $ins->bindValue(':ded', $r['deductions']);
        $ins->bindValue(':net', $r['net_pay']);
        if ($uid) { $ins->bindValue(':gen', $uid, PDO::PARAM_INT); } else { $ins->bindValue(':gen', null, PDO::PARAM_NULL); }
        $ok = $ins->execute();
        if ($ok) $count++;
      }
      return json_encode(['success' => true, 'inserted' => $count]);
    }
    if ($type === 'employee') {
      // Snapshot employees matching filters
      $sql = "SELECT e.*, d.dept_id FROM tblemployees e LEFT JOIN tbldepartments d ON d.dept_name = e.department WHERE 1=1";
      $params = [];
      if ($employee_id) { $sql .= " AND e.employee_id = :emp"; $params[':emp'] = $employee_id; }
      if ($department_id) { $sql .= " AND d.dept_id = :dept"; $params[':dept'] = $department_id; }
      if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND e.employee_id = :me_emp"; $params[':me_emp'] = $me['employee_id']; }
      $stmt = $conn->prepare($sql);
      foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
      $ins = $conn->prepare("INSERT INTO tblEmployeeReports (Employee_ID, Department_ID, Position, Basic_Salary, Status, Date_Hired, Generated_By) VALUES (:eid,:dept,:pos,:basic,:status,:dh,:gen)");
      $count = 0;
      foreach ($rows as $r){
        $ins->bindValue(':eid', (int)$r['employee_id'], PDO::PARAM_INT);
        if (!empty($r['dept_id'])) { $ins->bindValue(':dept', (int)$r['dept_id'], PDO::PARAM_INT); } else { $ins->bindValue(':dept', null, PDO::PARAM_NULL); }
        $ins->bindValue(':pos', $r['position']);
        $ins->bindValue(':basic', $r['basic_salary']);
        $ins->bindValue(':status', strtolower($r['status'] ?: 'active'));
        $ins->bindValue(':dh', $r['date_hired']);
        if ($uid) { $ins->bindValue(':gen', $uid, PDO::PARAM_INT); } else { $ins->bindValue(':gen', null, PDO::PARAM_NULL); }
        $ok = $ins->execute(); if ($ok) $count++;
      }
      return json_encode(['success' => true, 'inserted' => $count]);
    }
    if ($type === 'department') {
      // Aggregate per department
      $sql = "SELECT d.dept_id, d.dept_name, COUNT(e.employee_id) AS total_emp, COALESCE(SUM(e.basic_salary),0) AS total_salary
              FROM tbldepartments d
              LEFT JOIN tblemployees e ON e.department = d.dept_name
              WHERE 1=1";
      $params = [];
      if ($department_id) { $sql .= " AND d.dept_id = :dept"; $params[':dept'] = $department_id; }
      $sql .= " GROUP BY d.dept_id, d.dept_name";
      $stmt = $conn->prepare($sql);
      foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
      $ins = $conn->prepare("INSERT INTO tblDepartmentReports (Department_ID, Total_Employees, Total_Salary, Generated_By) VALUES (:dept,:emp,:sal,:gen)");
      $count = 0;
      foreach ($rows as $r){
        $ins->bindValue(':dept', (int)$r['dept_id'], PDO::PARAM_INT);
        $ins->bindValue(':emp', (int)$r['total_emp'], PDO::PARAM_INT);
        $ins->bindValue(':sal', $r['total_salary']);
        if ($uid) { $ins->bindValue(':gen', $uid, PDO::PARAM_INT); } else { $ins->bindValue(':gen', null, PDO::PARAM_NULL); }
        $ok = $ins->execute(); if ($ok) $count++;
      }
      return json_encode(['success' => true, 'inserted' => $count]);
    }
    if ($type === 'attendance') {
      // Summarize attendance per employee for range; store against latest attendance row in range (if any)
      // Fallback: if dates are missing, use a sensible default range (current month or month of provided date)
      if (!$start || !$end) {
        try {
          if ($start && !$end) {
            $d = new DateTime($start);
            $end = $d->format('Y-m-t');
          } elseif ($end && !$start) {
            $d = new DateTime($end);
            $start = $d->format('Y-m-01');
          } else {
            $today = new DateTime('today');
            $start = $today->format('Y-m-01');
            $end = $today->format('Y-m-t');
          }
        } catch (Exception $e) {
          $today = new DateTime('today');
          $start = $today->format('Y-m-01');
          $end = $today->format('Y-m-t');
        }
      }
      $sql = "SELECT e.employee_id, e.first_name, e.last_name
              FROM tblemployees e WHERE 1=1";
      $params = [];
      if ($employee_id) { $sql .= " AND e.employee_id = :emp"; $params[':emp'] = $employee_id; }
      if ($department_id) { $sql .= " AND EXISTS (SELECT 1 FROM tbldepartments d WHERE d.dept_id = :dept AND d.dept_name = e.department)"; $params[':dept'] = $department_id; }
      if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND e.employee_id = :me_emp"; $params[':me_emp'] = $me['employee_id']; }
      $stmt = $conn->prepare($sql);
      foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
      $stmt->execute();
      $emps = $stmt->fetchAll(PDO::FETCH_ASSOC);
      $count = 0;
      $ins = $conn->prepare("INSERT INTO tblAttendanceReports (Attendance_ID, Employee_ID, Period_Start, Period_End, Days_Present, Days_Absent, Days_Leave, Days_Late, Total_Hours_Worked, Generated_By)
                              VALUES (:aid,:eid,:ps,:pe,:dp,:da,:dl,:dlte,:hrs,:gen)");
      foreach ($emps as $e){
        $eid = (int)$e['employee_id'];
        // Aggregate attendance
        $a = $conn->prepare("SELECT status, COUNT(*) cnt FROM tblattendance WHERE employee_id=:eid AND attendance_date BETWEEN :s AND :e GROUP BY status");
        $a->bindValue(':eid', $eid, PDO::PARAM_INT);
        $a->bindValue(':s', $start);
        $a->bindValue(':e', $end);
        $a->execute();
        $by = ['present'=>0,'absent'=>0,'leave'=>0,'late'=>0];
        foreach ($a->fetchAll(PDO::FETCH_ASSOC) as $r){ $by[strtolower($r['status'])] = (int)$r['cnt']; }
        $h = $conn->prepare("SELECT time_in, time_out FROM tblattendance WHERE employee_id=:eid AND attendance_date BETWEEN :s AND :e AND time_in IS NOT NULL AND time_out IS NOT NULL");
        $h->bindValue(':eid', $eid, PDO::PARAM_INT);
        $h->bindValue(':s', $start);
        $h->bindValue(':e', $end);
        $h->execute();
        $hours = 0.0;
        foreach ($h->fetchAll(PDO::FETCH_ASSOC) as $row){
          $in = strtotime($row['time_in']); $out = strtotime($row['time_out']);
          if ($in !== false && $out !== false && $out > $in) { $diff = ($out - $in) / 3600.0; $hours += max(0.0, $diff - 1.0); }
        }
        $latestId = null;
        $w = $conn->prepare("SELECT attendance_id FROM tblattendance WHERE employee_id=:eid AND attendance_date BETWEEN :s AND :e ORDER BY attendance_date DESC, attendance_id DESC LIMIT 1");
        $w->bindValue(':eid', $eid, PDO::PARAM_INT);
        $w->bindValue(':s', $start);
        $w->bindValue(':e', $end);
        $w->execute();
        $latestId = $w->fetchColumn();
        if (!$latestId) { continue; }
        $ins->bindValue(':aid', (int)$latestId, PDO::PARAM_INT);
        $ins->bindValue(':eid', $eid, PDO::PARAM_INT);
        $ins->bindValue(':ps', $start);
        $ins->bindValue(':pe', $end);
        $ins->bindValue(':dp', (int)$by['present'], PDO::PARAM_INT);
        $ins->bindValue(':da', (int)$by['absent'], PDO::PARAM_INT);
        $ins->bindValue(':dl', (int)$by['leave'], PDO::PARAM_INT);
        $ins->bindValue(':dlte', (int)$by['late'], PDO::PARAM_INT);
        $ins->bindValue(':hrs', round($hours, 2));
        if ($uid) { $ins->bindValue(':gen', $uid, PDO::PARAM_INT); } else { $ins->bindValue(':gen', null, PDO::PARAM_NULL); }
        $ok = $ins->execute(); if ($ok) $count++;
      }
      return json_encode(['success' => true, 'inserted' => $count]);
    }
    if ($type === 'deduction') {
      // Generate deduction reports from payroll data and attendance-based deductions
      $count = 0;

      // Clear existing deduction reports for the same period and filters to prevent duplicates
      $deleteSql = "DELETE FROM tblDeductionReports WHERE 1=1";
      $deleteParams = [];
      if ($start) { $deleteSql .= " AND (Period_Start IS NULL OR Period_Start >= :start)"; $deleteParams[':start'] = $start; }
      if ($end) { $deleteSql .= " AND (Period_End IS NULL OR Period_End <= :end)"; $deleteParams[':end'] = $end; }
      if ($employee_id) { $deleteSql .= " AND Employee_ID = :emp"; $deleteParams[':emp'] = $employee_id; }
      if (!canSeeAll($me) && $me['employee_id']) { $deleteSql .= " AND Employee_ID = :me_emp"; $deleteParams[':me_emp'] = $me['employee_id']; }

      $deleteStmt = $conn->prepare($deleteSql);
      foreach ($deleteParams as $k => $v) { $deleteStmt->bindValue($k, $v); }
      $deleteStmt->execute();

      // First, try to get deductions from payroll records
      $sql = "SELECT p.payroll_id, p.employee_id, p.deductions, p.payroll_period_start, p.payroll_period_end, e.first_name, e.last_name FROM tblpayroll p INNER JOIN tblemployees e ON e.employee_id = p.employee_id WHERE p.deductions > 0";
      $params = [];
      if ($start) { $sql .= " AND p.payroll_period_start >= :start"; $params[':start'] = $start; }
      if ($end) { $sql .= " AND p.payroll_period_end <= :end"; $params[':end'] = $end; }
      if ($employee_id) { $sql .= " AND p.employee_id = :emp"; $params[':emp'] = $employee_id; }
      if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND p.employee_id = :me_emp"; $params[':me_emp'] = $me['employee_id']; }

      $stmt = $conn->prepare($sql);
      foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
      $stmt->execute();
      $payrollRows = $stmt->fetchAll(PDO::FETCH_ASSOC);

      $ins = $conn->prepare("INSERT INTO tblDeductionReports (Deduction_ID, Employee_ID, Payroll_ID, Deduction_Amount, Period_Start, Period_End, Generated_By) VALUES (:did,:eid,:pid,:amt,:ps,:pe,:gen)");

      // Get available deduction types for proper distribution
      $deductStmt = $conn->prepare("SELECT deduct_id, name, amount FROM tbldeductions ORDER BY deduct_id");
      $deductStmt->execute();
      $deductTypes = $deductStmt->fetchAll(PDO::FETCH_ASSOC);

      // Insert payroll-based deductions - distribute total deductions across different types
      foreach ($payrollRows as $r) {
        $totalDeductions = (float)$r['deductions'];
        $basicSalary = 0;

        // Get employee's basic salary for percentage calculations
        $salaryStmt = $conn->prepare("SELECT basic_salary FROM tblemployees WHERE employee_id = :eid");
        $salaryStmt->bindValue(':eid', (int)$r['employee_id'], PDO::PARAM_INT);
        $salaryStmt->execute();
        $salaryRow = $salaryStmt->fetch(PDO::FETCH_ASSOC);
        if ($salaryRow) {
          $basicSalary = (float)$salaryRow['basic_salary'];
        }

        if (!empty($deductTypes) && $basicSalary > 0) {
          // Distribute deductions across different types based on typical percentages
          foreach ($deductTypes as $deduct) {
            $amount = 0;
            if (stripos($deduct['name'], 'sss') !== false) {
              $amount = $basicSalary * 0.045; // 4.5% for SSS
            } elseif (stripos($deduct['name'], 'philhealth') !== false) {
              $amount = $basicSalary * 0.025; // 2.5% for PhilHealth
            } elseif (stripos($deduct['name'], 'pagibig') !== false || stripos($deduct['name'], 'pag-ibig') !== false) {
              $amount = min($basicSalary * 0.02, 100); // 2% of salary, max 100
            } elseif (stripos($deduct['name'], 'withholding') !== false || stripos($deduct['name'], 'tax') !== false) {
              // Calculate actual withholding tax based on salary
              $amount = computeWithholdingTaxLocal($basicSalary);
            } else {
              // For other deductions, use a portion of remaining total deductions
              $amount = min($deduct['amount'], $totalDeductions * 0.1); // 10% of total or fixed amount
            }

            if ($amount > 0) {
              $ins->bindValue(':did', (int)$deduct['deduct_id'], PDO::PARAM_INT);
              $ins->bindValue(':eid', (int)$r['employee_id'], PDO::PARAM_INT);
              $ins->bindValue(':pid', (int)$r['payroll_id'], PDO::PARAM_INT);
              $ins->bindValue(':amt', round($amount, 2));
              $ins->bindValue(':ps', $r['payroll_period_start']);
              $ins->bindValue(':pe', $r['payroll_period_end']);
              if ($uid) { $ins->bindValue(':gen', $uid, PDO::PARAM_INT); } else { $ins->bindValue(':gen', null, PDO::PARAM_NULL); }
              $ok = $ins->execute(); if ($ok) $count++;
            }
          }
        } else {
          // Fallback: create one entry with first available deduction type
          $firstDeductId = !empty($deductTypes) ? $deductTypes[0]['deduct_id'] : 1;
          $ins->bindValue(':did', (int)$firstDeductId, PDO::PARAM_INT);
          $ins->bindValue(':eid', (int)$r['employee_id'], PDO::PARAM_INT);
          $ins->bindValue(':pid', (int)$r['payroll_id'], PDO::PARAM_INT);
          $ins->bindValue(':amt', $totalDeductions);
          $ins->bindValue(':ps', $r['payroll_period_start']);
          $ins->bindValue(':pe', $r['payroll_period_end']);
          if ($uid) { $ins->bindValue(':gen', $uid, PDO::PARAM_INT); } else { $ins->bindValue(':gen', null, PDO::PARAM_NULL); }
          $ok = $ins->execute(); if ($ok) $count++;
        }
      }

      // If no payroll deductions found, generate from employee-deduction mappings if they exist
      if ($count === 0) {
        $sql = "SELECT ed.employee_id, ed.deduct_id, ed.value, d.name FROM tblemployee_deductions ed INNER JOIN tbldeductions d ON d.deduct_id = ed.deduct_id WHERE 1=1";
        $params = [];
        if ($employee_id) { $sql .= " AND ed.employee_id = :emp"; $params[':emp'] = $employee_id; }
        if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND ed.employee_id = :me_emp"; $params[':me_emp'] = $me['employee_id']; }
        $stmt = $conn->prepare($sql);
        foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $r){
          $ins->bindValue(':did', (int)$r['deduct_id'], PDO::PARAM_INT);
          $ins->bindValue(':eid', (int)$r['employee_id'], PDO::PARAM_INT);
          $ins->bindValue(':pid', null, PDO::PARAM_NULL);
          $ins->bindValue(':amt', $r['value'] !== null ? $r['value'] : 0.00);
          $ins->bindValue(':ps', $start ?: null);
          $ins->bindValue(':pe', $end ?: null);
          if ($uid) { $ins->bindValue(':gen', $uid, PDO::PARAM_INT); } else { $ins->bindValue(':gen', null, PDO::PARAM_NULL); }
          $ok = $ins->execute(); if ($ok) $count++;
        }
      }

      // If still no deductions found, create sample deduction records for all employees
      if ($count === 0) {
        $sql = "SELECT e.employee_id, e.first_name, e.last_name, e.basic_salary FROM tblemployees e WHERE e.status = 'active'";
        $params = [];
        if ($employee_id) { $sql .= " AND e.employee_id = :emp"; $params[':emp'] = $employee_id; }
        if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND e.employee_id = :me_emp"; $params[':me_emp'] = $me['employee_id']; }

        $stmt = $conn->prepare($sql);
        foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
        $stmt->execute();
        $employees = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Get available deduction types
        $deductStmt = $conn->prepare("SELECT deduct_id, name, amount FROM tbldeductions ORDER BY deduct_id LIMIT 5");
        $deductStmt->execute();
        $deductTypes = $deductStmt->fetchAll(PDO::FETCH_ASSOC);

        if (!empty($deductTypes)) {
          foreach ($employees as $emp) {
            foreach ($deductTypes as $deduct) {
              // Calculate deduction amount based on salary (example: SSS = 4.5% of salary, PhilHealth = 2.5%)
              $amount = 0;
              if (stripos($deduct['name'], 'sss') !== false) {
                $amount = $emp['basic_salary'] * 0.045; // 4.5% for SSS
              } elseif (stripos($deduct['name'], 'philhealth') !== false) {
                $amount = $emp['basic_salary'] * 0.025; // 2.5% for PhilHealth
              } elseif (stripos($deduct['name'], 'pagibig') !== false || stripos($deduct['name'], 'pag-ibig') !== false) {
                $amount = min($emp['basic_salary'] * 0.02, 100); // 2% of salary, max 100
              } elseif (stripos($deduct['name'], 'withholding') !== false || stripos($deduct['name'], 'tax') !== false) {
                // Calculate actual withholding tax based on salary
                $amount = computeWithholdingTaxLocal($emp['basic_salary']);
              } else {
                $amount = $deduct['amount']; // Use fixed amount from deduction type
              }

              $ins->bindValue(':did', (int)$deduct['deduct_id'], PDO::PARAM_INT);
              $ins->bindValue(':eid', (int)$emp['employee_id'], PDO::PARAM_INT);
              $ins->bindValue(':pid', null, PDO::PARAM_NULL);
              $ins->bindValue(':amt', round($amount, 2));
              $ins->bindValue(':ps', $start ?: null);
              $ins->bindValue(':pe', $end ?: null);
              if ($uid) { $ins->bindValue(':gen', $uid, PDO::PARAM_INT); } else { $ins->bindValue(':gen', null, PDO::PARAM_NULL); }
              $ok = $ins->execute(); if ($ok) $count++;
            }
          }
        }
      }

      return json_encode(['success' => true, 'inserted' => $count]);
    }
    http_response_code(400);
    return json_encode(['success' => false, 'message' => 'Unknown type']);
  } catch (Exception $e) {
    http_response_code(500);
    return json_encode(['success' => false, 'message' => 'Failed to generate']);
  }
}

// ===== New: List reports with filters =====
function listReports($conn){
  $type = isset($_GET['type']) ? strtolower(trim($_GET['type'])) : '';
  $me = currentUser($conn);
  $employee_id = isset($_GET['employee_id']) ? (int)$_GET['employee_id'] : 0;
  $department_id = isset($_GET['department_id']) ? (int)$_GET['department_id'] : 0;
  $start = isset($_GET['start_date']) ? $_GET['start_date'] : null;
  $end = isset($_GET['end_date']) ? $_GET['end_date'] : null;
  $status = isset($_GET['status']) ? strtolower(trim($_GET['status'])) : null;

  $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
  $limit = isset($_GET['limit']) ? max(1, min(200, intval($_GET['limit']))) : 25;
  $offset = ($page - 1) * $limit;

  if ($type === 'payroll'){
    $sql = "SELECT r.*, e.first_name, e.last_name FROM tblPayrollReports r INNER JOIN tblemployees e ON e.employee_id = r.Employee_ID WHERE 1=1";
    $params = [];
    if ($start) { $sql .= " AND r.Period_Start >= :start"; $params[':start'] = $start; }
    if ($end) { $sql .= " AND r.Period_End <= :end"; $params[':end'] = $end; }
    if ($employee_id) { $sql .= " AND r.Employee_ID = :emp"; $params[':emp'] = $employee_id; }
    if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND r.Employee_ID = :me_emp"; $params[':me_emp'] = $me['employee_id']; }
    $countSql = preg_replace('/SELECT.*FROM/i', 'SELECT COUNT(*) AS c FROM', $sql, 1);
    $cStmt = $conn->prepare($countSql);
    foreach ($params as $k=>$v){ $cStmt->bindValue($k,$v); }
    $cStmt->execute();
    $total = (int)$cStmt->fetchColumn();
    $sql .= " ORDER BY r.Report_ID DESC LIMIT :lim OFFSET :off";
    $stmt = $conn->prepare($sql);
    foreach ($params as $k=>$v){ $stmt->bindValue($k,$v); }
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if ($total === 0) {
      // Fallback: pull current payrolls directly if no snapshots exist
      $sql2 = "SELECT NULL AS Report_ID, p.payroll_id AS Payroll_ID, p.employee_id AS Employee_ID, p.payroll_period_start AS Period_Start, p.payroll_period_end AS Period_End, p.basic_salary AS Basic_Salary, p.deductions AS Total_Deductions, p.net_pay AS Net_Pay, NULL AS Generated_By, NULL AS Generated_At, e.first_name, e.last_name FROM tblpayroll p INNER JOIN tblemployees e ON e.employee_id = p.employee_id WHERE 1=1";
      $params2 = [];
      if ($start) { $sql2 .= " AND p.payroll_period_start >= :start2"; $params2[':start2'] = $start; }
      if ($end) { $sql2 .= " AND p.payroll_period_end <= :end2"; $params2[':end2'] = $end; }
      if ($employee_id) { $sql2 .= " AND p.employee_id = :emp2"; $params2[':emp2'] = $employee_id; }
      if (!canSeeAll($me) && $me['employee_id']) { $sql2 .= " AND p.employee_id = :me_emp2"; $params2[':me_emp2'] = $me['employee_id']; }
      $countSql2 = preg_replace('/SELECT.*FROM/i', 'SELECT COUNT(*) AS c FROM', $sql2, 1);
      $c2 = $conn->prepare($countSql2);
      foreach ($params2 as $k=>$v){ $c2->bindValue($k,$v); }
      $c2->execute();
      $total = (int)$c2->fetchColumn();
      $sql2 .= " ORDER BY p.payroll_id DESC LIMIT :lim2 OFFSET :off2";
      $stmt2 = $conn->prepare($sql2);
      foreach ($params2 as $k=>$v){ $stmt2->bindValue($k,$v); }
      $stmt2->bindValue(':lim2', $limit, PDO::PARAM_INT);
      $stmt2->bindValue(':off2', $offset, PDO::PARAM_INT);
      $stmt2->execute();
      $rows = $stmt2->fetchAll(PDO::FETCH_ASSOC);
    }
    return json_encode(['items'=>$rows,'total'=>$total,'page'=>$page,'limit'=>$limit]);
  }
  if ($type === 'attendance'){
    $sql = "SELECT r.*, e.first_name, e.last_name FROM tblAttendanceReports r INNER JOIN tblemployees e ON e.employee_id = r.Employee_ID WHERE 1=1";
    $params = [];
    if ($start) { $sql .= " AND r.Period_Start >= :start"; $params[':start'] = $start; }
    if ($end) { $sql .= " AND r.Period_End <= :end"; $params[':end'] = $end; }
    if ($employee_id) { $sql .= " AND r.Employee_ID = :emp"; $params[':emp'] = $employee_id; }
    if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND r.Employee_ID = :me_emp"; $params[':me_emp'] = $me['employee_id']; }
    $countSql = preg_replace('/SELECT.*FROM/i', 'SELECT COUNT(*) AS c FROM', $sql, 1);
    $cStmt = $conn->prepare($countSql);
    foreach ($params as $k=>$v){ $cStmt->bindValue($k,$v); }
    $cStmt->execute();
    $total = (int)$cStmt->fetchColumn();
    $sql .= " ORDER BY r.Report_ID DESC LIMIT :lim OFFSET :off";
    $stmt = $conn->prepare($sql);
    foreach ($params as $k=>$v){ $stmt->bindValue($k,$v); }
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return json_encode(['items'=>$rows,'total'=>$total,'page'=>$page,'limit'=>$limit]);
  }
  if ($type === 'employee'){
    $sql = "SELECT r.*, e.first_name, e.last_name, d.dept_name FROM tblEmployeeReports r INNER JOIN tblemployees e ON e.employee_id=r.Employee_ID LEFT JOIN tbldepartments d ON d.dept_id = r.Department_ID WHERE 1=1";
    $params = [];
    if ($employee_id) { $sql .= " AND r.Employee_ID = :emp"; $params[':emp'] = $employee_id; }
    if ($department_id) { $sql .= " AND r.Department_ID = :dept"; $params[':dept'] = $department_id; }
    if ($start) { $sql .= " AND r.Generated_At >= :start"; $params[':start'] = $start; }
    if ($end) { $sql .= " AND r.Generated_At <= :end"; $params[':end'] = $end; }
    if ($status) { $sql .= " AND r.Status = :status"; $params[':status'] = $status; }
    if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND r.Employee_ID = :me_emp"; $params[':me_emp'] = $me['employee_id']; }
    $countSql = preg_replace('/SELECT.*FROM/i', 'SELECT COUNT(*) AS c FROM', $sql, 1);
    $cStmt = $conn->prepare($countSql);
    foreach ($params as $k=>$v){ $cStmt->bindValue($k,$v); }
    $cStmt->execute();
    $total = (int)$cStmt->fetchColumn();
    $sql .= " ORDER BY r.Report_ID DESC LIMIT :lim OFFSET :off";
    $stmt = $conn->prepare($sql);
    foreach ($params as $k=>$v){ $stmt->bindValue($k,$v); }
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return json_encode(['items'=>$rows,'total'=>$total,'page'=>$page,'limit'=>$limit]);
  }
  if ($type === 'department'){
    $sql = "SELECT r.*, d.dept_name FROM tblDepartmentReports r INNER JOIN tbldepartments d ON d.dept_id = r.Department_ID WHERE 1=1";
    $params = [];
    if ($department_id) { $sql .= " AND r.Department_ID = :dept"; $params[':dept'] = $department_id; }
    if ($start) { $sql .= " AND r.Generated_At >= :start"; $params[':start'] = $start; }
    if ($end) { $sql .= " AND r.Generated_At <= :end"; $params[':end'] = $end; }
    $countSql = preg_replace('/SELECT.*FROM/i', 'SELECT COUNT(*) AS c FROM', $sql, 1);
    $cStmt = $conn->prepare($countSql);
    foreach ($params as $k=>$v){ $cStmt->bindValue($k,$v); }
    $cStmt->execute();
    $total = (int)$cStmt->fetchColumn();
    $sql .= " ORDER BY r.Report_ID DESC LIMIT :lim OFFSET :off";
    $stmt = $conn->prepare($sql);
    foreach ($params as $k=>$v){ $stmt->bindValue($k,$v); }
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return json_encode(['items'=>$rows,'total'=>$total,'page'=>$page,'limit'=>$limit]);
  }
  if ($type === 'deduction'){
    $sql = "SELECT r.*, d.name AS deduction_name, e.first_name, e.last_name FROM tblDeductionReports r INNER JOIN tbldeductions d ON d.deduct_id = r.Deduction_ID INNER JOIN tblemployees e ON e.employee_id = r.Employee_ID WHERE 1=1";
    $params = [];
    if ($employee_id) { $sql .= " AND r.Employee_ID = :emp"; $params[':emp'] = $employee_id; }
    if ($start) { $sql .= " AND (r.Period_Start IS NULL OR r.Period_Start >= :start)"; $params[':start'] = $start; }
    if ($end) { $sql .= " AND (r.Period_End IS NULL OR r.Period_End <= :end)"; $params[':end'] = $end; }
    // Optional filters: deduction by id or name fragment
    if (!empty($_GET['deduction_id'])) { $sql .= " AND r.Deduction_ID = :did"; $params[':did'] = (int)$_GET['deduction_id']; }
    if (!empty($_GET['deduction_name'])) { $sql .= " AND d.name LIKE :dname"; $params[':dname'] = '%' . $_GET['deduction_name'] . '%'; }
    if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND r.Employee_ID = :me_emp"; $params[':me_emp'] = $me['employee_id']; }
    $countSql = preg_replace('/SELECT.*FROM/i', 'SELECT COUNT(*) AS c FROM', $sql, 1);
    $cStmt = $conn->prepare($countSql);
    foreach ($params as $k=>$v){ $cStmt->bindValue($k,$v); }
    $cStmt->execute();
    $total = (int)$cStmt->fetchColumn();
    $sql .= " ORDER BY r.Report_ID DESC LIMIT :lim OFFSET :off";
    $stmt = $conn->prepare($sql);
    foreach ($params as $k=>$v){ $stmt->bindValue($k,$v); }
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return json_encode(['items'=>$rows,'total'=>$total,'page'=>$page,'limit'=>$limit]);
  }
  http_response_code(400);
  return json_encode(['items'=>[], 'total'=>0, 'page'=>1, 'limit'=>25]);
}

// ===== New: Download single report (JSON or CSV) =====
function downloadReport($conn){
  $type = isset($_GET['type']) ? strtolower(trim($_GET['type'])) : '';
  $id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
  if (!$type || !$id) { http_response_code(400); echo json_encode(['success'=>false]); return; }
  $map = [
    'payroll' => [ 'table' => 'tblPayrollReports', 'pk' => 'Report_ID' ],
    'attendance' => [ 'table' => 'tblAttendanceReports', 'pk' => 'Report_ID' ],
    'employee' => [ 'table' => 'tblEmployeeReports', 'pk' => 'Report_ID' ],
    'department' => [ 'table' => 'tblDepartmentReports', 'pk' => 'Report_ID' ],
    'deduction' => [ 'table' => 'tblDeductionReports', 'pk' => 'Report_ID' ],
  ];
  if (!isset($map[$type])) { http_response_code(400); echo json_encode(['success'=>false]); return; }
  $t = $map[$type];
  $stmt = $conn->prepare("SELECT * FROM {$t['table']} WHERE {$t['pk']} = :id LIMIT 1");
  $stmt->bindValue(':id', $id, PDO::PARAM_INT);
  $stmt->execute();
  $row = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$row) { http_response_code(404); echo json_encode(['success'=>false]); return; }
  header('Content-Type: application/json');
  echo json_encode(['success'=>true, 'item'=>$row]);
}

// ===== New: Export CSV for a report type =====
function exportReports($conn){
  $type = isset($_GET['type']) ? strtolower(trim($_GET['type'])) : '';
  $format = isset($_GET['format']) ? strtolower(trim($_GET['format'])) : 'csv';
  // Reuse the listReports builder by calling it and decoding JSON
  $_GET['page'] = 1; $_GET['limit'] = 100000; // export all within filters
  $json = listReports($conn);
  $data = json_decode($json, true);
  $rows = isset($data['items']) && is_array($data['items']) ? $data['items'] : [];

  if ($format === 'xls') {
    // HTML table-based XLS export to allow Excel to auto-fit columns and avoid #####
    $fname = $type ? $type . '_reports_' . date('Ymd_His') . '.xls' : ('reports_' . date('Ymd_His') . '.xls');
    header('Content-Type: application/vnd.ms-excel; charset=UTF-8');
    header('Content-Disposition: attachment; filename=' . $fname);
    header('Pragma: no-cache');
    header('Expires: 0');

    if (!$rows){ echo '<table><tr><td>No data</td></tr></table>'; exit; }
    // Build headers based on type as in CSV branch
    $headers = [];
    if ($type === 'payroll') {
      $headers = ['Report ID','Payroll ID','Employee ID','Employee Name','Period Start','Period End','Basic Salary','Total Deductions','Net Pay','Generated By','Generated At'];
    } elseif ($type === 'attendance') {
      $headers = ['Report_ID','Employee_ID','first_name','last_name','Period_Start','Period_End','Days_Present','Days_Absent','Days_Leave','Days_Late','Total_Hours_Worked','Generated_By','Generated_At'];
    } elseif ($type === 'employee') {
      $headers = ['Report_ID','Employee_ID','dept_name','Position','Basic_Salary','Status','Date_Hired','Generated_By','Generated_At'];
    } elseif ($type === 'department') {
      $headers = ['Report_ID','Department_ID','dept_name','Total_Employees','Total_Salary','Generated_By','Generated_At'];
    } elseif ($type === 'deduction') {
      $headers = ['Report_ID','Employee_ID','first_name','last_name','Deduction_ID','deduction_name','Deduction_Amount','Payroll_ID','Period_Start','Period_End','Generated_By','Generated_At'];
    } else {
      $headers = array_keys($rows[0]);
    }
    // Simple width heuristic: set a reasonable width based on header and sample cell length
    $widths = [];
    foreach ($headers as $col) { $widths[$col] = max(12, strlen((string)$col) + 2); }
    $sampleCount = min(100, count($rows));
    for ($i=0; $i<$sampleCount; $i++) {
      $r = $rows[$i];
      foreach ($headers as $col) {
        $val = isset($r[$col]) ? $r[$col] : (isset($r[strtolower($col)]) ? $r[strtolower($col)] : '');
        $len = strlen((string)$val);
        if ($len + 2 > $widths[$col]) $widths[$col] = min(60, $len + 2);
      }
    }
    echo '<html><head><meta charset="UTF-8"><style>table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:4px;text-align:left;white-space:nowrap}</style></head><body>';
    echo '<table><thead><tr>';
    foreach ($headers as $h) {
      $w = isset($widths[$h]) ? $widths[$h] : 12;
      echo '<th style="width:' . (int)$w . 'ch">' . htmlspecialchars($h) . '</th>';
    }
    echo '</tr></thead><tbody>';
    if ($type === 'payroll') {
      // Build username map for Generated_By
      $genIds = [];
      foreach ($rows as $r) { if (!empty($r['Generated_By'])) { $genIds[(int)$r['Generated_By']] = true; } }
      $genMap = [];
      if (!empty($genIds)) {
        $ids = array_keys($genIds);
        $place = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conn->prepare("SELECT user_id, username FROM tblusers WHERE user_id IN ($place)");
        foreach ($ids as $i => $id) { $stmt->bindValue($i+1, $id, PDO::PARAM_INT); }
        $stmt->execute();
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $u) { $genMap[(int)$u['user_id']] = $u['username']; }
      }
      $sumBasic = 0.0; $sumDed = 0.0; $sumNet = 0.0;
      foreach ($rows as $r) {
        $reportId = isset($r['Report_ID']) ? (int)$r['Report_ID'] : (isset($r['report_id']) ? (int)$r['report_id'] : 0);
        $payrollId = isset($r['Payroll_ID']) ? (int)$r['Payroll_ID'] : 0;
        $empId = isset($r['Employee_ID']) ? (int)$r['Employee_ID'] : 0;
        $empName = trim((($r['first_name'] ?? '') . ' ' . ($r['last_name'] ?? '')));
        $ps = isset($r['Period_Start']) ? substr((string)$r['Period_Start'], 0, 10) : '';
        $pe = isset($r['Period_End']) ? substr((string)$r['Period_End'], 0, 10) : '';
        $basic = (float)($r['Basic_Salary'] ?? 0);
        $ded = (float)($r['Total_Deductions'] ?? 0);
        $net = (float)($r['Net_Pay'] ?? 0);
        $genById = isset($r['Generated_By']) ? (int)$r['Generated_By'] : null;
        $genBy = $genById !== null && isset($genMap[$genById]) ? $genMap[$genById] : ($genById !== null ? (string)$genById : '');
        $genAt = isset($r['Generated_At']) ? (string)$r['Generated_At'] : '';
        $sumBasic += $basic; $sumDed += $ded; $sumNet += $net;
        echo '<tr>';
        $vals = [ $reportId, $payrollId, $empId, $empName, $ps, $pe, number_format($basic,2,'.',''), number_format($ded,2,'.',''), number_format($net,2,'.',''), $genBy, $genAt ];
        foreach ($vals as $v) { echo '<td>' . htmlspecialchars((string)$v) . '</td>'; }
        echo '</tr>';
      }
      echo '<tr>';
      $totals = [ '', '', '', 'TOTAL', '', '', number_format($sumBasic,2,'.',''), number_format($sumDed,2,'.',''), number_format($sumNet,2,'.',''), '', '' ];
      foreach ($totals as $t) { echo '<td>' . htmlspecialchars((string)$t) . '</td>'; }
      echo '</tr>';
    } else {
      foreach ($rows as $r) {
        echo '<tr>';
        foreach ($headers as $h) {
          $val = isset($r[$h]) ? $r[$h] : (isset($r[strtolower($h)]) ? $r[strtolower($h)] : '');
          echo '<td>' . htmlspecialchars(is_scalar($val) ? (string)$val : json_encode($val)) . '</td>';
        }
        echo '</tr>';
      }
    }
    echo '</tbody></table></body></html>';
    exit;
  }

  header('Content-Type: text/csv');
  $fname = $type ? $type . '_reports_' . date('Ymd_His') . '.csv' : ('reports_' . date('Ymd_His') . '.csv');
  header('Content-Disposition: attachment; filename="' . $fname . '"');

  // Fallback: if payroll export has no snapshot rows, pull directly from tblpayroll
  if ($type === 'payroll' && (!$rows || count($rows) === 0)) {
    $me = currentUser($conn);
    $start = isset($_GET['start_date']) ? $_GET['start_date'] : null;
    $end = isset($_GET['end_date']) ? $_GET['end_date'] : null;
    $employee_id = isset($_GET['employee_id']) ? (int)$_GET['employee_id'] : 0;
    $sql = "SELECT p.payroll_id, p.employee_id, p.payroll_period_start, p.payroll_period_end, p.basic_salary, p.deductions AS total_deductions, p.net_pay, NULL AS Generated_By, NULL AS Generated_At, e.first_name, e.last_name FROM tblpayroll p INNER JOIN tblemployees e ON e.employee_id = p.employee_id WHERE 1=1";
    $params = [];
    if ($start) { $sql .= " AND p.payroll_period_start >= :start"; $params[':start'] = $start; }
    if ($end) { $sql .= " AND p.payroll_period_end <= :end"; $params[':end'] = $end; }
    if ($employee_id) { $sql .= " AND p.employee_id = :emp"; $params[':emp'] = $employee_id; }
    if (!canSeeAll($me) && $me['employee_id']) { $sql .= " AND p.employee_id = :me_emp"; $params[':me_emp'] = $me['employee_id']; }
    $stmt = $conn->prepare($sql);
    foreach ($params as $k=>$v){ $stmt->bindValue($k,$v); }
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
  }

  $out = fopen('php://output', 'w');
  if (!$rows){ fputcsv($out, ['No data']); fclose($out); exit; }

  if ($type === 'payroll') {
    // Build username map for Generated_By
    $genIds = [];
    foreach ($rows as $r) { if (!empty($r['Generated_By'])) { $genIds[(int)$r['Generated_By']] = true; } }
    $genMap = [];
    if (!empty($genIds)) {
      $ids = array_keys($genIds);
      $place = implode(',', array_fill(0, count($ids), '?'));
      $stmt = $conn->prepare("SELECT user_id, username FROM tblusers WHERE user_id IN ($place)");
      foreach ($ids as $i => $id) { $stmt->bindValue($i+1, $id, PDO::PARAM_INT); }
      $stmt->execute();
      foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $u) { $genMap[(int)$u['user_id']] = $u['username']; }
    }

    // Header for Excel (CSV) payroll export
    $headers = [
      'Report ID','Payroll ID','Employee ID','Employee Name','Period Start','Period End',
      'Basic Salary','Total Deductions','Net Pay','Generated By','Generated At'
    ];
    fputcsv($out, $headers);

    $sumBasic = 0.0; $sumDed = 0.0; $sumNet = 0.0;
    foreach ($rows as $r) {
      $reportId = isset($r['Report_ID']) ? (int)$r['Report_ID'] : (isset($r['report_id']) ? (int)$r['report_id'] : 0);
      $payrollId = isset($r['Payroll_ID']) ? (int)$r['Payroll_ID'] : 0;
      $empId = isset($r['Employee_ID']) ? (int)$r['Employee_ID'] : 0;
      $empName = trim((($r['first_name'] ?? '') . ' ' . ($r['last_name'] ?? '')));
      $ps = isset($r['Period_Start']) ? substr((string)$r['Period_Start'], 0, 10) : '';
      $pe = isset($r['Period_End']) ? substr((string)$r['Period_End'], 0, 10) : '';
      $basic = (float)($r['Basic_Salary'] ?? 0);
      $ded = (float)($r['Total_Deductions'] ?? 0);
      $net = (float)($r['Net_Pay'] ?? 0);
      $genById = isset($r['Generated_By']) ? (int)$r['Generated_By'] : null;
      $genBy = $genById !== null && isset($genMap[$genById]) ? $genMap[$genById] : ($genById !== null ? (string)$genById : '');
      $genAt = isset($r['Generated_At']) ? (string)$r['Generated_At'] : '';

      $sumBasic += $basic; $sumDed += $ded; $sumNet += $net;

      fputcsv($out, [
        $reportId,
        $payrollId,
        $empId,
        $empName,
        $ps,
        $pe,
        number_format($basic, 2, '.', ''),
        number_format($ded, 2, '.', ''),
        number_format($net, 2, '.', ''),
        $genBy,
        $genAt
      ]);
    }
    // Optional totals row
    fputcsv($out, [
      '', '', '', 'TOTAL', '', '',
      number_format($sumBasic, 2, '.', ''),
      number_format($sumDed, 2, '.', ''),
      number_format($sumNet, 2, '.', ''),
      '', ''
    ]);
  } else {
    // Default export: dump keys then values as-is
    fputcsv($out, array_keys($rows[0]));
    foreach ($rows as $r){ fputcsv($out, array_map(function($v){ return is_scalar($v) ? $v : json_encode($v); }, $r)); }
  }

  fclose($out);
  exit;
}
?>
