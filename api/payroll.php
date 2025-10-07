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

  // Helper: get user name from user ID
  function getUserName($conn, $userId) {
    if (!$userId) return '';
    try {
      $stmt = $conn->prepare("SELECT u.username, e.first_name, e.last_name 
                               FROM tblusers u
                               LEFT JOIN tblemployees e ON e.employee_id = u.employee_id
                               WHERE u.user_id = :user_id LIMIT 1");
      $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
      $stmt->execute();
      $user = $stmt->fetch(PDO::FETCH_ASSOC);
      
      if ($user) {
        // Prefer employee name if available, otherwise use username
        if (!empty($user['first_name']) || !empty($user['last_name'])) {
          return trim($user['first_name'] . ' ' . $user['last_name']);
        } else {
          return $user['username'];
        }
      }
    } catch (Exception $e) {
      // Ignore errors and return empty string
    }
    return '';
  }

  // Helper: send an in-app notification to all admins
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
    } catch (Exception $e) {
      return 0;
    }
  }

  // Helper: send an in-app notification to all HR users
  function notifyHR($conn, $type, $message, $actorUserId = null) {
    try {
      $sel = $conn->prepare("SELECT employee_id FROM tblusers WHERE role = 'hr' AND employee_id IS NOT NULL AND employee_id > 0");
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
    } catch (Exception $e) {
      return 0;
    }
  }

  $operation = '';
  if ($_SERVER['REQUEST_METHOD'] == 'GET'){
    $operation = isset($_GET['operation']) ? $_GET['operation'] : '';
  } else if($_SERVER['REQUEST_METHOD'] == 'POST'){
    $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
  }

  switch ($operation) {
    case 'generatePayroll':
      echo generatePayroll($conn);
      break;
    case 'listPayroll':
      echo listPayroll($conn);
      break;
    case 'getPayrolls':
      echo getPayrolls($conn);
      break;
    case 'updateStatus':
      echo updateStatus($conn);
      break;
    case 'listPayslipHistory':
      echo listPayslipHistory($conn);
      break;
    case 'archivePayslip':
      echo archivePayslip($conn);
      break;
    case 'deletePayslipHistory':
      echo deletePayslipHistory($conn);
      break;
    case 'archivePayrollBulk':
      echo archivePayrollBulk($conn);
      break;
    case 'listPayrollArchive':
      echo listPayrollArchive($conn);
      break;
    case 'unarchiveAllPayroll':
      echo unarchiveAllPayroll($conn);
      break;
    case 'createPayrollBatch':
      echo createPayrollBatch($conn);
      break;
    case 'listPayrollBatches':
      echo listPayrollBatches($conn);
      break;
    case 'getPayrollBatch':
      echo getPayrollBatch($conn);
      break;
    case 'listPayrollBatchEmployees':
      echo listPayrollBatchEmployees($conn);
      break;
    case 'updatePayrollBatch':
      echo updatePayrollBatch($conn);
      break;
    case 'setPayrollBatchStatus':
      echo setPayrollBatchStatus($conn);
      break;
        default:
      echo json_encode([]);
  }

  /**
   * CALCULATE STANDARD DEDUCTIONS BREAKDOWN
   * Computes SSS, PhilHealth, Pag-IBIG, and withholding tax
   * Based on Philippine labor law requirements
   */
  function computeDeductionsBreakdown($gross){
    $gross = max(0.0, floatval($gross));
    if ($gross <= 0.0) {
      return [
        'sss' => 0.0,
        'philhealth' => 0.0,
        'pagibig' => 0.0,
        'provident_fund' => 0.0,
        'tax' => 0.0,
        'total' => 0.0,
      ];
    }
    // SSS: 5% of gross salary
    $sss_initial = round($gross * 0.05, 2);
    // Provident Fund: 10% of SSS amount (deducted from SSS, not added to total)
    $provident_fund = round($sss_initial * 0.10, 2);
    // Net SSS: SSS amount minus provident fund
    $sss = round($sss_initial - $provident_fund, 2);
    // PhilHealth: (clamped(Gross, 10k..100k) * 5%) / 2
    $phBase = min(100000.0, max(10000.0, $gross));
    $philhealth = round($phBase * 0.05 / 2, 2);
    // Pag-IBIG: Gross * 2%
    $pagibig = round($gross * 0.02, 2);
    // Withholding tax (monthly brackets, TRAIN)
    $tax = computeWithholdingTax($gross);
    $total = round($sss + $philhealth + $pagibig + $tax, 2);
    return [
      'sss' => $sss,
      'philhealth' => $philhealth,
      'pagibig' => $pagibig,
      'provident_fund' => $provident_fund,
      'tax' => $tax,
      'total' => $total,
    ];
  }

  /**
   * CALCULATE WITHHOLDING TAX
   * Computes monthly withholding tax using TRAIN law brackets
   * Progressive tax calculation for Philippine tax system
   */
  function computeWithholdingTax($monthly){
    $m = max(0.0, floatval($monthly));
    // Brackets:
    // 0 – 20,833 => 0
    // 20,834 – 33,333 => 20% of excess over 20,833
    // 33,334 – 66,667 => 2,500 + 25% of excess over 33,333
    // 66,668 – 166,667 => 10,833.33 + 30% of excess over 66,667
    // 166,668 – 666,667 => 40,833.33 + 32% of excess over 166,667
    // Over 666,667 => 200,833.33 + 35% of excess over 666,667
    if ($m <= 20833.0) return 0.0;
    if ($m <= 33333.0) return round(($m - 20833.0) * 0.20, 2);
    if ($m <= 66667.0) return round(2500.0 + ($m - 33333.0) * 0.25, 2);
    if ($m <= 166667.0) return round(10833.33 + ($m - 66667.0) * 0.30, 2);
    if ($m <= 666667.0) return round(40833.33 + ($m - 166667.0) * 0.32, 2);
    return round(200833.33 + ($m - 666667.0) * 0.35, 2);
  }

  /**
   * GENERATE EMPLOYEE PAYROLL
   * Creates payroll record with attendance and overtime calculations
   * Integrates with attendance deductions and period management
   */
  function generatePayroll($conn){
    $data = json_decode($_POST['json'], true);
    $empId = $data['employee_id'];
    $start = $data['payroll_period_start'];
    $end = $data['payroll_period_end'];
    $overtimeHours = floatval($data['overtime_hours']);
    $overtimeRate = floatval($data['overtime_rate']);
    $deductionsPosted = floatval($data['deductions']);

    // fetch employee salary
    $stmt = $conn->prepare('SELECT basic_salary, salary_rate_type FROM tblemployees WHERE employee_id = :id');
    $stmt->bindParam(':id', $empId);
    $stmt->execute();
    $emp = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$emp) return json_encode(0);
    $basic = floatval($emp['basic_salary']);
    $rateType = isset($emp['salary_rate_type']) ? strtolower(trim($emp['salary_rate_type'])) : 'monthly';

    // Calculate attendance deductions
    $attendanceDeductions = calculateAttendanceDeductionsForPayroll($conn, $empId, $start, $end);
    
    // Prefer computed overtime from attendance and approved requests
    $computedOtHours = isset($attendanceDeductions['total_overtime_hours']) ? floatval($attendanceDeductions['total_overtime_hours']) : 0.0;
    $computedOtPay = isset($attendanceDeductions['total_overtime_pay']) ? floatval($attendanceDeductions['total_overtime_pay']) : 0.0;

    if ($computedOtHours > 0 || $computedOtPay > 0) {
      $overtimeHours = $computedOtHours;
      $overtimePay = $computedOtPay;
    } else {
      $overtimePay = $overtimeHours * $overtimeRate;
    }

    // Base pay depends on salary rate and selected period
    $basePay = 0.0;
    if ($rateType === 'monthly') {
      // Use monthly salary: full month if period is same day-of-month to same day-of-month; else pro-rate by days/30
      try {
        $dtStart = new DateTime($start);
        $dtEnd = new DateTime($end);
        // Normalize times
        $dtStart->setTime(0,0,0);
        $dtEnd->setTime(0,0,0);
        $sameDay = ($dtStart->format('d') === $dtEnd->format('d')) && ($dtEnd > $dtStart);
        if ($sameDay) {
          $diff = $dtStart->diff($dtEnd);
          $months = ($diff->y * 12) + $diff->m; // only whole months when same day-of-month
          if ($months <= 0) { $months = 1; }
          $basePay = $basic * $months;
        } else {
          $days = max(0, (int)round(($dtEnd->getTimestamp() - $dtStart->getTimestamp()) / 86400));
          if ($days <= 0) { $days = 1; }
          $basePay = ($basic / 30.0) * $days; // pro-rate by 30-day month standard
        }
      } catch (Exception $e) {
        // Fallback to one month if parsing fails
        $basePay = $basic;
      }
    } else {
      if (isset($attendanceDeductions['total_work_days']) && isset($attendanceDeductions['daily_wage'])) {
        $basePay = floatval($attendanceDeductions['daily_wage']) * (int)$attendanceDeductions['total_work_days'];
      }
    }

    $gross = $basePay + $overtimePay;
    $break = computeDeductionsBreakdown($gross);
    $deductionsTotal = $break['total'] + $attendanceDeductions['total_deductions'];
    $net = $gross - $deductionsTotal;

    // Ensure payroll period exists and upsert workday summary for this employee/period
    $periodId = ensurePayrollPeriod($conn, $start, $end);
    upsertEmployeeWorkdaySummary($conn, $empId, $periodId, [
      'total_workdays' => isset($attendanceDeductions['total_work_days']) ? (int)$attendanceDeductions['total_work_days'] : 0,
      'days_present' => isset($attendanceDeductions['days_present']) ? (int)$attendanceDeductions['days_present'] : 0,
      'days_absent' => isset($attendanceDeductions['days_absent']) ? (int)$attendanceDeductions['days_absent'] : 0,
      'days_leave' => isset($attendanceDeductions['days_leave']) ? (int)$attendanceDeductions['days_leave'] : 0,
      'days_late' => isset($attendanceDeductions['days_late']) ? (int)$attendanceDeductions['days_late'] : 0,
      'total_hours_worked' => isset($attendanceDeductions['total_hours_worked']) ? (float)$attendanceDeductions['total_hours_worked'] : 0.0
    ]);

    $sql = "INSERT INTO tblpayroll(employee_id, payroll_period_start, payroll_period_end, basic_salary, total_overtime_hours, overtime_pay, deductions, net_pay)
            VALUES(:employee_id, :start, :end, :basic, :ot_hours, :ot_pay, :deductions, :net)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':employee_id', $empId);
    $stmt->bindParam(':start', $start);
    $stmt->bindParam(':end', $end);
    $stmt->bindParam(':basic', $basic);
    $stmt->bindParam(':ot_hours', $overtimeHours);
    $stmt->bindParam(':ot_pay', $overtimePay);
    $stmt->bindParam(':deductions', $deductionsTotal);
    $stmt->bindParam(':net', $net);
    $stmt->execute();

    $ok = $stmt->rowCount() > 0;
    if ($ok) {
      try {
        // Notify the employee that their payroll has been processed
        $processorName = '';
        if (isset($_SESSION['user_id'])) {
          $processorName = getUserName($conn, (int)$_SESSION['user_id']);
        }
        
        // Get employee name for the message
        $empName = 'Employee';
        try {
          $empStmt = $conn->prepare('SELECT first_name, last_name FROM tblemployees WHERE employee_id = :emp_id LIMIT 1');
          $empStmt->bindParam(':emp_id', $empId, PDO::PARAM_INT);
          $empStmt->execute();
          $empRow = $empStmt->fetch(PDO::FETCH_ASSOC);
          if ($empRow) {
            $empName = trim($empRow['first_name'] . ' ' . $empRow['last_name']);
            if (empty($empName)) {
              $empName = 'Employee';
            }
          }
        } catch (Exception $e) { /* ignore errors */ }
        
        $empMsg = $processorName ? 
          $processorName . ' processed ' . $empName . '’s payroll for the period ' . $start . ' → ' . $end :
          $empName . '’s payroll has been processed for the period ' . $start . ' → ' . $end;
        $empIns = $conn->prepare('INSERT INTO tblnotifications(employee_id, message, type, actor_user_id) VALUES(:eid, :msg, :type, :actor)');
        $empIns->bindValue(':eid', $empId, PDO::PARAM_INT);
        $empIns->bindValue(':msg', $empMsg);
        $empIns->bindValue(':type', 'payroll_processed');
        if (isset($_SESSION['user_id'])) { $empIns->bindValue(':actor', (int)$_SESSION['user_id'], PDO::PARAM_INT); }
        else { $empIns->bindValue(':actor', null, PDO::PARAM_NULL); }
        $empIns->execute();
        
        // If an admin processed the payroll, notify HR users
        if (isset($_SESSION['role']) && strtolower((string)$_SESSION['role']) === 'admin') {
          $actor = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
          // Fetch employee name for message
          $nq = $conn->prepare('SELECT first_name, last_name FROM tblemployees WHERE employee_id = :id LIMIT 1');
          $nq->bindValue(':id', $empId, PDO::PARAM_INT);
          $nq->execute();
          $nm = $nq->fetch(PDO::FETCH_ASSOC);
          $fullName = $nm ? trim(($nm['first_name'] ?? '') . ' ' . ($nm['last_name'] ?? '')) : ('Employee #' . $empId);
          $processorName = '';
          if (isset($_SESSION['user_id'])) {
            $processorName = getUserName($conn, (int)$_SESSION['user_id']);
          }
          
          // Get department info for the employee
          $deptInfo = '';
          try {
            $deptStmt = $conn->prepare('SELECT department FROM tblemployees WHERE employee_id = :emp_id LIMIT 1');
            $deptStmt->bindParam(':emp_id', $empId, PDO::PARAM_INT);
            $deptStmt->execute();
            $deptRow = $deptStmt->fetch(PDO::FETCH_ASSOC);
            if ($deptRow && !empty($deptRow['department'])) {
              $deptInfo = $deptRow['department'] . ' department';
            }
          } catch (Exception $e) { /* ignore errors */ }
          
          $msg = $processorName && !empty($deptInfo) ? 
            $processorName . ' processed ' . $deptInfo . ' payroll for the period ' . $start . ' → ' . $end . ' (Employee: ' . $fullName . ')' :
            ($processorName ? 
              $processorName . ' processed payroll for ' . $fullName . ' for the period ' . $start . ' → ' . $end :
              'Admin processed payroll for ' . $fullName . ' for the period ' . $start . ' → ' . $end);
          
          // Notify HR users
          notifyHR($conn, 'payroll_processed', $msg, $actor);
        }
        
        if (isset($_SESSION['role']) && strtolower((string)$_SESSION['role']) === 'hr') {
          $actor = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
          // Fetch employee name for message
          $nq = $conn->prepare('SELECT first_name, last_name FROM tblemployees WHERE employee_id = :id LIMIT 1');
          $nq->bindValue(':id', $empId, PDO::PARAM_INT);
          $nq->execute();
          $nm = $nq->fetch(PDO::FETCH_ASSOC);
          $fullName = $nm ? trim(($nm['first_name'] ?? '') . ' ' . ($nm['last_name'] ?? '')) : ('Employee #' . $empId);
          $processorName = '';
          if (isset($_SESSION['user_id'])) {
            $processorName = getUserName($conn, (int)$_SESSION['user_id']);
          }
          
          // Get department info for the employee
          $deptInfo = '';
          try {
            $deptStmt = $conn->prepare('SELECT department FROM tblemployees WHERE employee_id = :emp_id LIMIT 1');
            $deptStmt->bindParam(':emp_id', $empId, PDO::PARAM_INT);
            $deptStmt->execute();
            $deptRow = $deptStmt->fetch(PDO::FETCH_ASSOC);
            if ($deptRow && !empty($deptRow['department'])) {
              $deptInfo = $deptRow['department'] . ' department';
            }
          } catch (Exception $e) { /* ignore errors */ }
          
          $msg = $processorName && !empty($deptInfo) ? 
            $processorName . ' processed ' . $deptInfo . ' payroll for the period ' . $start . ' → ' . $end . ' (Employee: ' . $fullName . ')' :
            ($processorName ? 
              $processorName . ' processed payroll for ' . $fullName . ' for the period ' . $start . ' → ' . $end :
              'HR processed payroll for ' . $fullName . ' for the period ' . $start . ' → ' . $end);
          notifyAdmins($conn, 'payroll_processed', $msg, $actor);
        }
      } catch (Exception $e) { /* ignore notification errors */ }
    }
    return json_encode($ok ? 1 : 0);
  }

  /**
   * Calculate attendance deductions for payroll generation
   */
  function calculateAttendanceDeductionsForPayroll($conn, $employeeId, $startDate, $endDate) {
    // Get system settings
    $stmt = $conn->prepare("SELECT setting_key, setting_value FROM tblsystem_settings 
                           WHERE setting_key IN (
                             'work_hours_per_day', 'lunch_hours_per_day', 'grace_period_minutes', 
                             'rounding_interval_minutes', 'overtime_multiplier', 'late_deduction_enabled',
                             'undertime_deduction_enabled', 'absent_deduction_enabled'
                           )");
    $stmt->execute();
    $settingsRows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $settings = [];
    foreach ($settingsRows as $row) {
      $settings[$row['setting_key']] = $row['setting_value'];
    }
    
    // Set default values if not found
    $defaults = [
      'work_hours_per_day' => 12,
      'lunch_hours_per_day' => 1,
      'grace_period_minutes' => 15,
      'rounding_interval_minutes' => 15,
      'overtime_multiplier' => 1.25,
      'late_deduction_enabled' => 1,
      'undertime_deduction_enabled' => 1,
      'absent_deduction_enabled' => 1
    ];
    
    foreach ($defaults as $key => $default) {
      if (!isset($settings[$key])) {
        $settings[$key] = $default;
      }
    }
    
    // Get employee salary information
    $stmt = $conn->prepare("SELECT basic_salary, salary_rate_type FROM tblemployees WHERE employee_id = :id");
    $stmt->bindParam(':id', $employeeId, PDO::PARAM_INT);
    $stmt->execute();
    $employee = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$employee) {
      return ['total_deductions' => 0, 'breakdown' => []];
    }
    
    // Get attendance data for the period
    $stmt = $conn->prepare("SELECT * FROM tblattendance 
                           WHERE employee_id = :emp_id 
                           AND attendance_date BETWEEN :start AND :end
                           ORDER BY attendance_date");
    $stmt->bindParam(':emp_id', $employeeId, PDO::PARAM_INT);
    $stmt->bindParam(':start', $startDate);
    $stmt->bindParam(':end', $endDate);
    $stmt->execute();
    $attendance = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get approved overtime and undertime requests
    $stmt = $conn->prepare("SELECT * FROM tblovertime_requests 
                           WHERE employee_id = :emp_id 
                           AND work_date BETWEEN :start AND :end 
                           AND status = 'approved'");
    $stmt->bindParam(':emp_id', $employeeId, PDO::PARAM_INT);
    $stmt->bindParam(':start', $startDate);
    $stmt->bindParam(':end', $endDate);
    $stmt->execute();
    $overtime = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $stmt = $conn->prepare("SELECT * FROM tblundertime_requests 
                           WHERE employee_id = :emp_id 
                           AND work_date BETWEEN :start AND :end 
                           AND status = 'approved'");
    $stmt->bindParam(':emp_id', $employeeId, PDO::PARAM_INT);
    $stmt->bindParam(':start', $startDate);
    $stmt->bindParam(':end', $endDate);
    $stmt->execute();
    $undertime = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Calculate deductions using the same logic as the dedicated API
    $workHoursPerDay = (float)$settings['work_hours_per_day'];
    $lunchHoursPerDay = (float)$settings['lunch_hours_per_day'];
    $gracePeriodMinutes = (float)$settings['grace_period_minutes'];
    $roundingInterval = (float)$settings['rounding_interval_minutes'];
    $overtimeMultiplier = isset($settings['overtime_multiplier']) ? (float)$settings['overtime_multiplier'] : 1.25;
    
    $lateDeductionEnabled = (bool)$settings['late_deduction_enabled'];
    $undertimeDeductionEnabled = (bool)$settings['undertime_deduction_enabled'];
    $absentDeductionEnabled = (bool)$settings['absent_deduction_enabled'];
    
    $basicSalary = (float)$employee['basic_salary'];
    $salaryRateType = $employee['salary_rate_type'];
    
    // Convert monthly salary to daily if needed
    $dailyWage = $basicSalary;
    if ($salaryRateType === 'monthly') {
      // Using 30 days per month for daily conversion
      $dailyWage = $basicSalary / 30;
    } elseif ($salaryRateType === 'hourly') {
      $dailyWage = $basicSalary * $workHoursPerDay;
    }
    
    $paidHours = $workHoursPerDay - $lunchHoursPerDay;
    $hourlyRate = $paidHours > 0 ? ($dailyWage / $paidHours) : 0;
    $perMinuteRate = $hourlyRate / 60.0;
    
    $totalLateDeduction = 0;
    $totalUndertimeDeduction = 0;
    $totalAbsentDeduction = 0;
    $totalOvertimeMinutes = 0;
    $totalOvertimePay = 0;
    $totalWorkDays = 0;
    $daysPresent = 0;
    $daysAbsent = 0;
    $daysLeave = 0;
    $daysLate = 0;
    $totalHoursWorked = 0.0;
    
    // Process each day
    foreach ($attendance as $record) {
      $status = $record['status'];
      $timeIn = $record['time_in'];
      $timeOut = $record['time_out'];
      
      // Count status occurrences
      if ($status === 'present') { $daysPresent++; }
      elseif ($status === 'late') { $daysLate++; }
      elseif ($status === 'leave') { $daysLeave++; }
      elseif ($status === 'absent') { $daysAbsent++; }

      // Accumulate total hours worked (approximate; subtract configured lunch hours)
      if (!empty($timeIn) && !empty($timeOut)) {
        $inTs = strtotime($timeIn);
        $outTs = strtotime($timeOut);
        if ($inTs !== false && $outTs !== false) {
          $diffHrs = ($outTs - $inTs) / 3600.0;
          if ($diffHrs > 0) {
            $worked = max(0.0, $diffHrs - $lunchHoursPerDay);
            $totalHoursWorked += $worked;
          }
        }
      }
      
      if ($status === 'absent') {
        if ($absentDeductionEnabled) {
          $absentMinutes = $paidHours * 60;
          $dailyAbsentDeduction = ($dailyWage / $paidHours / 60) * $absentMinutes;
          $totalAbsentDeduction += $dailyAbsentDeduction;
        }
      } else {
        // Count work day
        $totalWorkDays++;
        // Calculate late deduction
        if ($lateDeductionEnabled && $timeIn) {
          $lateMinutes = calculateLateMinutesForPayroll($timeIn, $gracePeriodMinutes, $roundingInterval);
          if ($lateMinutes > 0) {
            $dailyLateDeduction = ($dailyWage / $paidHours / 60) * $lateMinutes;
            $totalLateDeduction += $dailyLateDeduction;
          }
        }
        
        // Calculate undertime deduction
        if ($undertimeDeductionEnabled && $timeOut) {
          $undertimeMinutes = calculateUndertimeMinutesForPayroll($timeOut, $workHoursPerDay, $roundingInterval);
          if ($undertimeMinutes > 0) {
            $dailyUndertimeDeduction = ($dailyWage / $paidHours / 60) * $undertimeMinutes;
            $totalUndertimeDeduction += $dailyUndertimeDeduction;
          }
        }
        // Calculate overtime from time out
        if ($timeOut) {
          $otMinutes = calculateOvertimeMinutesForPayroll($timeOut, $workHoursPerDay, $roundingInterval);
          if ($otMinutes > 0) {
            $totalOvertimeMinutes += $otMinutes;
            $totalOvertimePay += ($perMinuteRate * $otMinutes * $overtimeMultiplier);
          }
        }
      }
    }
    
    // Add approved overtime requests
    foreach ($overtime as $req) {
      $hrs = isset($req['hours']) ? (float)$req['hours'] : 0.0;
      if ($hrs > 0) {
        $mins = $hrs * 60.0;
        $totalOvertimeMinutes += $mins;
        $totalOvertimePay += ($perMinuteRate * $mins * $overtimeMultiplier);
      }
    }

    $totalDeductions = $totalLateDeduction + $totalUndertimeDeduction + $totalAbsentDeduction;
    
    return [
      'total_deductions' => round($totalDeductions, 2),
      'breakdown' => [
        'late_deduction' => round($totalLateDeduction, 2),
        'undertime_deduction' => round($totalUndertimeDeduction, 2),
        'absent_deduction' => round($totalAbsentDeduction, 2)
      ],
      'total_overtime_hours' => round($totalOvertimeMinutes / 60.0, 2),
      'total_overtime_pay' => round($totalOvertimePay, 2),
      'total_work_days' => (int)$totalWorkDays,
      'daily_wage' => round($dailyWage, 2),
      'days_present' => (int)$daysPresent,
      'days_absent' => (int)$daysAbsent,
      'days_leave' => (int)$daysLeave,
      'days_late' => (int)$daysLate,
      'total_hours_worked' => round($totalHoursWorked, 2)
    ];
  }

  /**
   * Calculate late minutes for payroll (simplified version)
   */
  function calculateLateMinutesForPayroll($timeIn, $gracePeriod, $roundingInterval) {
    $timeInObj = new DateTime($timeIn);
    $scheduledTime = new DateTime('08:00:00'); // Default 8:00 AM
    
    $diffMinutes = ($timeInObj->getTimestamp() - $scheduledTime->getTimestamp()) / 60;
    
    if ($diffMinutes <= $gracePeriod) {
      return 0; // Within grace period
    }
    
    // Apply rounding if configured
    if ($roundingInterval > 0) {
      $diffMinutes = ceil($diffMinutes / $roundingInterval) * $roundingInterval;
    }
    
    return max(0, $diffMinutes);
  }

  /**
   * Calculate undertime minutes for payroll (simplified version)
   */
  function calculateUndertimeMinutesForPayroll($timeOut, $workHoursPerDay, $roundingInterval) {
    $timeOutObj = new DateTime($timeOut);
    $scheduledEndTime = new DateTime('20:00:00'); // Default 8:00 PM
    
    $diffMinutes = ($scheduledEndTime->getTimestamp() - $timeOutObj->getTimestamp()) / 60;
    
    if ($diffMinutes <= 0) {
      return 0; // No undertime
    }
    
    // Apply rounding if configured
    if ($roundingInterval > 0) {
      $diffMinutes = ceil($diffMinutes / $roundingInterval) * $roundingInterval;
    }
    
    return $diffMinutes;
  }

  function calculateOvertimeMinutesForPayroll($timeOut, $workHoursPerDay, $roundingInterval) {
    $timeOutObj = new DateTime($timeOut);
    $scheduledEndTime = new DateTime('20:00:00'); // Default 8:00 PM

    $diffMinutes = ($timeOutObj->getTimestamp() - $scheduledEndTime->getTimestamp()) / 60;
    if ($diffMinutes <= 0) {
      return 0; // No overtime
    }
    // Apply rounding if configured
    if ($roundingInterval > 0) {
      $diffMinutes = floor($diffMinutes / $roundingInterval) * $roundingInterval;
    }
    return $diffMinutes;
  }

  function listPayroll($conn){
    $sql = "SELECT p.*, e.first_name, e.last_name
            FROM tblpayroll p
            INNER JOIN tblemployees e ON e.employee_id = p.employee_id
            LEFT JOIN tblpayroll_archive a ON a.payroll_id = p.payroll_id
            WHERE a.payroll_id IS NULL
              AND NOT EXISTS (
                SELECT 1
                FROM tblpayroll_batch_employees be
                INNER JOIN tblpayroll_by_batch b ON b.batch_id = be.batch_id
                WHERE be.employee_id = p.employee_id
                  AND b.payroll_period_start = p.payroll_period_start
                  AND b.payroll_period_end = p.payroll_period_end
              )";
    $params = [];
    if (!empty($_GET['start_date'])) {
      $sql .= " AND p.payroll_period_start >= :start_date";
      $params[':start_date'] = $_GET['start_date'];
    }
    if (!empty($_GET['end_date'])) {
      $sql .= " AND p.payroll_period_end <= :end_date";
      $params[':end_date'] = $_GET['end_date'];
    }
    $sql .= " ORDER BY p.payroll_id DESC";
    $stmt = $conn->prepare($sql);
    foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    // Attach computed deduction breakdowns based on stored net + deductions
    foreach ($rows as &$r) {
      $gross = floatval($r['net_pay']) + floatval($r['deductions']);
      $bk = computeDeductionsBreakdown($gross);
      $r['sss_deduction'] = $bk['sss'];
      $r['philhealth_deduction'] = $bk['philhealth'];
      $r['pagibig_deduction'] = $bk['pagibig'];
      $r['provident_fund_deduction'] = $bk['provident_fund'];
      $r['tax_deduction'] = $bk['tax'];
    }
    unset($r);
    return json_encode($rows);
  }

  function getPayrolls($conn){
    // For employee portal: requires employee_id
    $empId = isset($_GET['employee_id']) ? (int)$_GET['employee_id'] : 0;
    if (!$empId) { return json_encode([]); }

    // 1) Main payroll rows (standard source for active payslips)
    $sql1 = "SELECT p.*, e.first_name, e.last_name
             FROM tblpayroll p
             INNER JOIN tblemployees e ON e.employee_id = p.employee_id
             WHERE p.employee_id = :emp
             ORDER BY p.payroll_id DESC";
    $stmt1 = $conn->prepare($sql1);
    $stmt1->bindValue(':emp', $empId, PDO::PARAM_INT);
    $stmt1->execute();
    $rows1 = $stmt1->fetchAll(PDO::FETCH_ASSOC) ?: [];
    foreach ($rows1 as &$r) {
      $gross = floatval($r['net_pay']) + floatval($r['deductions']);
      $bk = computeDeductionsBreakdown($gross);
      $r['sss_deduction'] = $bk['sss'];
      $r['philhealth_deduction'] = $bk['philhealth'];
      $r['pagibig_deduction'] = $bk['pagibig'];
      $r['provident_fund_deduction'] = $bk['provident_fund'];
      $r['tax_deduction'] = $bk['tax'];
    }
    unset($r);

    // 2) Batch-derived rows not present in main payroll (backward compatibility)
    $sql2 = "SELECT 
                NULL AS payroll_id,
                be.employee_id,
                b.payroll_period_start,
                b.payroll_period_end,
                be.basic_salary,
                0 AS total_overtime_hours,
                be.overtime_pay,
                be.deductions,
                be.net_pay,
                CASE WHEN LOWER(b.status) = 'completed' THEN 'paid' ELSE 'processed' END AS status,
                NULL AS paid_at,
                NULL AS paid_by,
                NULL AS slip_downloaded_at,
                0 AS slip_download_count,
                b.created_at,
                e.first_name,
                e.last_name
             FROM tblpayroll_batch_employees be
             INNER JOIN tblpayroll_by_batch b ON b.batch_id = be.batch_id
             INNER JOIN tblemployees e ON e.employee_id = be.employee_id
             WHERE be.employee_id = :emp
               AND NOT EXISTS (
                 SELECT 1 FROM tblpayroll p 
                 WHERE p.employee_id = be.employee_id
                   AND p.payroll_period_start = b.payroll_period_start
                   AND p.payroll_period_end = b.payroll_period_end
               )
             ORDER BY b.created_at DESC, be.batch_emp_id DESC";
    $stmt2 = $conn->prepare($sql2);
    $stmt2->bindValue(':emp', $empId, PDO::PARAM_INT);
    $stmt2->execute();
    $rows2 = $stmt2->fetchAll(PDO::FETCH_ASSOC) ?: [];
    foreach ($rows2 as &$r2) {
      $gross = floatval($r2['net_pay']) + floatval($r2['deductions']);
      $bk = computeDeductionsBreakdown($gross);
      $r2['sss_deduction'] = $bk['sss'];
      $r2['philhealth_deduction'] = $bk['philhealth'];
      $r2['pagibig_deduction'] = $bk['pagibig'];
      $r2['provident_fund_deduction'] = $bk['provident_fund'];
      $r2['tax_deduction'] = $bk['tax'];
    }
    unset($r2);

    // Merge: main first, then batch-derived
    $rows = array_merge($rows1, $rows2);

    return json_encode($rows);
  }

  function updateStatus($conn){
    // Expect POST: payroll_id, status, paid_by (optional)
    $payrollId = isset($_POST['payroll_id']) ? (int)$_POST['payroll_id'] : 0;
    $status = isset($_POST['status']) ? strtolower(trim($_POST['status'])) : '';
    $paidBy = isset($_POST['paid_by']) ? (int)$_POST['paid_by'] : null;
    // If marking as paid and no paid_by provided, use current session user if available
    if ($status === 'paid' && (!$paidBy || $paidBy <= 0) && isset($_SESSION['user_id'])) {
      $paidBy = (int)$_SESSION['user_id'];
    }

    if (!$payrollId || !in_array($status, ['processed','paid'])) {
      http_response_code(400);
      return json_encode(['success' => false, 'message' => 'Invalid parameters']);
    }

    if ($status === 'paid') {
      $sql = "UPDATE tblpayroll SET status='paid', paid_at=NOW(), paid_by=:paid_by WHERE payroll_id=:id";
    } else {
      $sql = "UPDATE tblpayroll SET status='processed', paid_at=NULL, paid_by=NULL WHERE payroll_id=:id";
    }

    $stmt = $conn->prepare($sql);
    $stmt->bindValue(':id', $payrollId, PDO::PARAM_INT);
    if ($status === 'paid') {
      $stmt->bindValue(':paid_by', $paidBy, PDO::PARAM_INT);
    }
    $ok = $stmt->execute();
    // Notify employee when payslip is marked as paid
    if ($ok && $status === 'paid') {
      try {
        $sel = $conn->prepare("SELECT employee_id, payroll_period_start, payroll_period_end FROM tblpayroll WHERE payroll_id = :id LIMIT 1");
        $sel->bindValue(':id', $payrollId, PDO::PARAM_INT);
        $sel->execute();
        $row = $sel->fetch(PDO::FETCH_ASSOC);
        if ($row && (int)$row['employee_id'] > 0) {
          $eid = (int)$row['employee_id'];
          $period = '';
          if (!empty($row['payroll_period_start']) && !empty($row['payroll_period_end'])) {
            $period = $row['payroll_period_start'] . ' → ' . $row['payroll_period_end'];
          }
          $processorName = '';
          if (isset($_SESSION['user_id'])) {
            $processorName = getUserName($conn, (int)$_SESSION['user_id']);
          }
          
          // Get employee name for the message
          $empName = 'Employee';
          try {
            $empStmt = $conn->prepare('SELECT first_name, last_name FROM tblemployees WHERE employee_id = :emp_id LIMIT 1');
            $empStmt->bindParam(':emp_id', $eid, PDO::PARAM_INT);
            $empStmt->execute();
            $empRow = $empStmt->fetch(PDO::FETCH_ASSOC);
            if ($empRow) {
              $empName = trim($empRow['first_name'] . ' ' . $empRow['last_name']);
              if (empty($empName)) {
                $empName = 'Employee';
              }
            }
          } catch (Exception $e) { /* ignore errors */ }
          
          $msg = $processorName ? 
            $processorName . ' paid ' . $empName . '’s payslip' . ($period ? ' (' . $period . ')' : '') :
            $empName . '’s payslip has been paid' . ($period ? ' (' . $period . ')' : '');
          $ins = $conn->prepare('INSERT INTO tblnotifications(employee_id, message, type, actor_user_id) VALUES(:eid, :msg, :type, :actor)');
          $type = 'payslip_paid';
          $ins->bindValue(':eid', $eid, PDO::PARAM_INT);
          $ins->bindValue(':msg', $msg);
          $ins->bindValue(':type', $type);
          if (isset($_SESSION['user_id'])) { $ins->bindValue(':actor', (int)$_SESSION['user_id'], PDO::PARAM_INT); }
          else { $ins->bindValue(':actor', null, PDO::PARAM_NULL); }
          $ins->execute();
          
          // If an admin paid the payslip, notify HR users
          if (isset($_SESSION['role']) && strtolower((string)$_SESSION['role']) === 'admin') {
            $actor = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
            $processorName = '';
            if ($actor) {
              $processorName = getUserName($conn, $actor);
            }
            
            // Get employee name for the message
            $empName = 'Employee';
            try {
              $empStmt = $conn->prepare('SELECT first_name, last_name FROM tblemployees WHERE employee_id = :emp_id LIMIT 1');
              $empStmt->bindParam(':emp_id', $eid, PDO::PARAM_INT);
              $empStmt->execute();
              $empRow = $empStmt->fetch(PDO::FETCH_ASSOC);
              if ($empRow) {
                $empName = trim($empRow['first_name'] . ' ' . $empRow['last_name']);
                if (empty($empName)) {
                  $empName = 'Employee';
                }
              }
            } catch (Exception $e) { /* ignore errors */ }
            
            // Get department info for the employee
            $deptInfo = '';
            try {
              $deptStmt = $conn->prepare('SELECT department FROM tblemployees WHERE employee_id = :emp_id LIMIT 1');
              $deptStmt->bindParam(':emp_id', $eid, PDO::PARAM_INT);
              $deptStmt->execute();
              $deptRow = $deptStmt->fetch(PDO::FETCH_ASSOC);
              if ($deptRow && !empty($deptRow['department'])) {
                $deptInfo = $deptRow['department'] . ' department';
              }
            } catch (Exception $e) { /* ignore errors */ }
            
            $msg = $processorName && !empty($deptInfo) ? 
              $processorName . ' processed ' . $deptInfo . ' payroll for the period ' . $period . ' (Employee: ' . $empName . ')' :
              ($processorName ? 
                $processorName . ' paid ' . $empName . '’s payslip for the period ' . $period :
                'Admin paid ' . $empName . '’s payslip for the period ' . $period);
            
            // Notify HR users
            notifyHR($conn, 'payslip_paid', $msg, $actor);
          }
        }
      } catch (Exception $e) { /* ignore notification errors */ }
    }
    return json_encode(['success' => $ok]);
  }
function listPayslipHistory($conn){
    $empId = isset($_GET['employee_id']) ? (int)$_GET['employee_id'] : 0;
    if (!$empId) { return json_encode([]); }
    $sql = "SELECT h.*, e.first_name, e.last_name,
                   p.status, p.paid_at,
                   h.total_deductions AS tbldeductions,
                   COALESCE(p.created_at, h.generated_at) AS created_at
            FROM tblpayslip_history h
            INNER JOIN tblemployees e ON e.employee_id = h.employee_id
            LEFT JOIN tblpayroll p ON p.payroll_id = h.payroll_id
            WHERE h.employee_id = :emp
            ORDER BY h.generated_at DESC, h.history_id DESC";
    $stmt = $conn->prepare($sql);
    $stmt->bindValue(':emp', $empId, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    // Attach computed deduction breakdowns based on stored net + total_deductions
    foreach ($rows as &$r) {
      $gross = floatval($r['net_pay']) + floatval($r['total_deductions']);
      $bk = computeDeductionsBreakdown($gross);
      $r['sss_deduction'] = $bk['sss'];
      $r['philhealth_deduction'] = $bk['philhealth'];
      $r['pagibig_deduction'] = $bk['pagibig'];
      $r['provident_fund_deduction'] = $bk['provident_fund'];
      $r['tax_deduction'] = $bk['tax'];
    }
    unset($r);
    return json_encode($rows);
  }

  function archivePayslip($conn){
    $payload = [];
    if (isset($_POST['json'])) { $payload = json_decode($_POST['json'], true) ?: []; }
    $payrollId = isset($payload['payroll_id']) ? (int)$payload['payroll_id'] : (isset($_POST['payroll_id']) ? (int)$_POST['payroll_id'] : 0);
    $employeeId = isset($payload['employee_id']) ? (int)$payload['employee_id'] : (isset($_POST['employee_id']) ? (int)$_POST['employee_id'] : 0);
    $generatedBy = isset($payload['generated_by']) ? (int)$payload['generated_by'] : (isset($_POST['generated_by']) ? (int)$_POST['generated_by'] : null);

    if (!$payrollId || !$employeeId) {
      http_response_code(400);
      return json_encode(['success' => false, 'message' => 'Missing parameters']);
    }

    // Verify payroll exists and belongs to employee
    $stmt = $conn->prepare("SELECT * FROM tblpayroll WHERE payroll_id = :pid AND employee_id = :emp");
    $stmt->bindValue(':pid', $payrollId, PDO::PARAM_INT);
    $stmt->bindValue(':emp', $employeeId, PDO::PARAM_INT);
    $stmt->execute();
    $p = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$p) { http_response_code(404); return json_encode(['success' => false, 'message' => 'Payroll not found']); }

    // Prevent duplicate archives for same payroll & employee
    $chk = $conn->prepare("SELECT COUNT(*) FROM tblpayslip_history WHERE payroll_id = :pid AND employee_id = :emp");
    $chk->bindValue(':pid', $payrollId, PDO::PARAM_INT);
    $chk->bindValue(':emp', $employeeId, PDO::PARAM_INT);
    $chk->execute();
    $exists = (int)$chk->fetchColumn() > 0;
    if ($exists) { return json_encode(['success' => true, 'message' => 'Already archived']); }

    $total_overtime_hours = isset($p['total_overtime_hours']) ? (float)$p['total_overtime_hours'] : 0.0;
    $overtime_pay = isset($p['overtime_pay']) ? (float)$p['overtime_pay'] : 0.0;
    $total_deductions = isset($p['deductions']) ? (float)$p['deductions'] : 0.0;
    $basic_salary = isset($p['basic_salary']) ? (float)$p['basic_salary'] : 0.0;
    $net_pay = isset($p['net_pay']) ? (float)$p['net_pay'] : 0.0;

    $gross = $net_pay + $total_deductions;
    $breakdown = computeDeductionsBreakdown($gross);
    $snapshot = [ 'payroll' => $p, 'deduction_breakdown' => $breakdown ];
    $snapshot_json = json_encode($snapshot);

    $sql = "INSERT INTO tblpayslip_history (
              payroll_id, employee_id, payroll_period_start, payroll_period_end, basic_salary,
              total_overtime_hours, overtime_pay, total_deductions, net_pay,
              snapshot_details, file_path, generated_by, generated_at
            ) VALUES (
              :pid, :emp, :start, :end, :basic_salary,
              :total_overtime_hours, :overtime_pay, :total_deductions, :net_pay,
              :snapshot_details, NULL, :generated_by, NOW()
            )";
    $ins = $conn->prepare($sql);
    $ins->bindValue(':pid', $payrollId, PDO::PARAM_INT);
    $ins->bindValue(':emp', $employeeId, PDO::PARAM_INT);
    $ins->bindValue(':start', $p['payroll_period_start']);
    $ins->bindValue(':end', $p['payroll_period_end']);
    $ins->bindValue(':basic_salary', $basic_salary);
    $ins->bindValue(':total_overtime_hours', $total_overtime_hours);
    $ins->bindValue(':overtime_pay', $overtime_pay);
    $ins->bindValue(':total_deductions', $total_deductions);
    $ins->bindValue(':net_pay', $net_pay);
    $ins->bindValue(':snapshot_details', $snapshot_json);
    if ($generatedBy !== null) { $ins->bindValue(':generated_by', $generatedBy, PDO::PARAM_INT); }
    else { $ins->bindValue(':generated_by', null, PDO::PARAM_NULL); }

    try {
      $ok = $ins->execute();
      if (!$ok) {
        $errorInfo = $ins->errorInfo();
        error_log('Archive payslip database error: ' . print_r($errorInfo, true));
        return json_encode(['success' => false, 'message' => 'Database error: ' . $errorInfo[2]]);
      }
      return json_encode(['success' => $ok]);
    } catch (Exception $e) {
      error_log('Archive payslip exception: ' . $e->getMessage());
      return json_encode(['success' => false, 'message' => 'Database exception: ' . $e->getMessage()]);
    }
  }

  function deletePayslipHistory($conn){
    $payload = [];
    if (isset($_POST['json'])) { $payload = json_decode($_POST['json'], true) ?: []; }
    $payrollId = isset($payload['payroll_id']) ? (int)$payload['payroll_id'] : (isset($_POST['payroll_id']) ? (int)$_POST['payroll_id'] : 0);
    $employeeId = isset($payload['employee_id']) ? (int)$payload['employee_id'] : (isset($_POST['employee_id']) ? (int)$_POST['employee_id'] : 0);
    if (!$payrollId || !$employeeId) { http_response_code(400); return json_encode(['success' => false, 'message' => 'Missing payroll ID or employee ID']); }
    try {
      $stmt = $conn->prepare("DELETE FROM tblpayslip_history WHERE payroll_id = :pid AND employee_id = :emp");
      $stmt->bindValue(':pid', $payrollId, PDO::PARAM_INT);
      $stmt->bindValue(':emp', $employeeId, PDO::PARAM_INT);
      $ok = $stmt->execute();
      if (!$ok) {
        $errorInfo = $stmt->errorInfo();
        error_log('Delete payslip history database error: ' . print_r($errorInfo, true));
        return json_encode(['success' => false, 'message' => 'Database error: ' . $errorInfo[2]]);
      }
      return json_encode(['success' => $ok]);
    } catch (Exception $e) {
      error_log('Delete payslip history exception: ' . $e->getMessage());
      return json_encode(['success' => false, 'message' => 'Database exception: ' . $e->getMessage()]);
    }
  }

  // Bulk archive payrolls into tblpayroll_archive
  function archivePayrollBulk($conn){
    $payload = [];
    if (isset($_POST['json'])) { $payload = json_decode($_POST['json'], true) ?: []; }
    $ids = isset($payload['payroll_ids']) && is_array($payload['payroll_ids']) ? $payload['payroll_ids'] : [];
    $reason = isset($payload['reason']) ? trim($payload['reason']) : '';
    $archivedBy = null;
    if (isset($_SESSION['user_id'])) { $archivedBy = (int)$_SESSION['user_id']; }

    if (empty($ids)) { http_response_code(400); return json_encode(['success' => false, 'message' => 'No payroll IDs provided']); }

    $ins = $conn->prepare("INSERT INTO tblpayroll_archive (payroll_id, employee_id, payroll_period_start, payroll_period_end, basic_salary, status, archived_reason, archived_by, archived_at)
                           VALUES (:pid, :emp, :start, :end, :basic_salary, :status, :reason, :archived_by, NOW())");
    $sel = $conn->prepare("SELECT * FROM tblpayroll WHERE payroll_id = :pid LIMIT 1");
    $chk = $conn->prepare("SELECT COUNT(*) FROM tblpayroll_archive WHERE payroll_id = :pid");

    $succeeded = 0; $skipped = 0; $failed = 0;
    foreach ($ids as $id) {
      $pid = (int)$id; if (!$pid) { $skipped++; continue; }
      $chk->bindValue(':pid', $pid, PDO::PARAM_INT);
      $chk->execute();
      if ((int)$chk->fetchColumn() > 0) { $skipped++; continue; }
      $sel->bindValue(':pid', $pid, PDO::PARAM_INT);
      $sel->execute();
      $p = $sel->fetch(PDO::FETCH_ASSOC);
      if (!$p) { $skipped++; continue; }
      try {
        $ins->bindValue(':pid', (int)$p['payroll_id'], PDO::PARAM_INT);
        $ins->bindValue(':emp', (int)$p['employee_id'], PDO::PARAM_INT);
        $ins->bindValue(':start', $p['payroll_period_start']);
        $ins->bindValue(':end', $p['payroll_period_end']);
        $ins->bindValue(':basic_salary', (float)$p['basic_salary']);
        $ins->bindValue(':status', strtolower(trim($p['status'] ?? 'processed')));
        if ($reason !== '') { $ins->bindValue(':reason', $reason, PDO::PARAM_STR); } else { $ins->bindValue(':reason', null, PDO::PARAM_NULL); }
        if ($archivedBy !== null) { $ins->bindValue(':archived_by', $archivedBy, PDO::PARAM_INT); } else { $ins->bindValue(':archived_by', null, PDO::PARAM_NULL); }
        $ok = $ins->execute();
        if ($ok) { $succeeded++; } else { $failed++; }
      } catch (Exception $e) { $failed++; }
    }

    return json_encode(['success' => true, 'succeeded' => $succeeded, 'skipped' => $skipped, 'failed' => $failed]);
  }

  // List archived payrolls from tblpayroll_archive
  function listPayrollArchive($conn){
    $sql = "SELECT a.*, e.first_name, e.last_name, e.department
            FROM tblpayroll_archive a
            INNER JOIN tblemployees e ON e.employee_id = a.employee_id
            ORDER BY a.archived_at DESC, a.archive_id DESC";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return json_encode($rows);
  }

  // Unarchive all (clear archive table)
  function unarchiveAllPayroll($conn){
    $stmt = $conn->prepare("DELETE FROM tblpayroll_archive");
    $ok = $stmt->execute();
    return json_encode(['success' => $ok]);
  }

// Helpers for employee workday summary persistence
function ensurePayrollPeriod($conn, $start, $end) {
  $sel = $conn->prepare("SELECT period_id FROM tblpayroll_period WHERE period_start = :start AND period_end = :end LIMIT 1");
  $sel->bindValue(':start', $start);
  $sel->bindValue(':end', $end);
  $sel->execute();
  $pid = $sel->fetchColumn();
  if ($pid) { return (int)$pid; }
  $ins = $conn->prepare("INSERT INTO tblpayroll_period (period_start, period_end, status) VALUES (:start, :end, 'open')");
  $ins->bindValue(':start', $start);
  $ins->bindValue(':end', $end);
  $ins->execute();
  return (int)$conn->lastInsertId();
}

function upsertEmployeeWorkdaySummary($conn, $employeeId, $periodId, $data) {
  $sql = "INSERT INTO tblemployee_workday_summary
            (employee_id, period_id, total_workdays, days_present, days_absent, days_leave, days_late, total_hours_worked, created_at, updated_at)
          VALUES
            (:employee_id, :period_id, :total_workdays, :days_present, :days_absent, :days_leave, :days_late, :total_hours_worked, NOW(), NOW())
          ON DUPLICATE KEY UPDATE
            total_workdays = VALUES(total_workdays),
            days_present = VALUES(days_present),
            days_absent = VALUES(days_absent),
            days_leave = VALUES(days_leave),
            days_late = VALUES(days_late),
            total_hours_worked = VALUES(total_hours_worked),
            updated_at = NOW()";
  $stmt = $conn->prepare($sql);
  $stmt->bindValue(':employee_id', $employeeId, PDO::PARAM_INT);
  $stmt->bindValue(':period_id', $periodId, PDO::PARAM_INT);
  $stmt->bindValue(':total_workdays', isset($data['total_workdays']) ? (int)$data['total_workdays'] : 0, PDO::PARAM_INT);
  $stmt->bindValue(':days_present', isset($data['days_present']) ? (int)$data['days_present'] : 0, PDO::PARAM_INT);
  $stmt->bindValue(':days_absent', isset($data['days_absent']) ? (int)$data['days_absent'] : 0, PDO::PARAM_INT);
  $stmt->bindValue(':days_leave', isset($data['days_leave']) ? (int)$data['days_leave'] : 0, PDO::PARAM_INT);
  $stmt->bindValue(':days_late', isset($data['days_late']) ? (int)$data['days_late'] : 0, PDO::PARAM_INT);
  $stmt->bindValue(':total_hours_worked', isset($data['total_hours_worked']) ? (float)$data['total_hours_worked'] : 0.0);
  $stmt->execute();
}
/**
   * Create a payroll batch record
   * Accepts: batch_name, payroll_period_start (or period_start), payroll_period_end (or period_end), department (optional), notes (optional)
   * Returns: { success: bool, batch_id: int, total_employees: int }
   */
  function createPayrollBatch($conn){
    $payload = [];
    if (isset($_POST['json'])) { $payload = json_decode($_POST['json'], true) ?: []; }
    else { $payload = $_POST; }

    $name = isset($payload['batch_name']) ? trim($payload['batch_name']) : '';
    $start = isset($payload['payroll_period_start']) ? $payload['payroll_period_start'] : (isset($payload['period_start']) ? $payload['period_start'] : '');
    $end = isset($payload['payroll_period_end']) ? $payload['payroll_period_end'] : (isset($payload['period_end']) ? $payload['period_end'] : '');
    $department = isset($payload['department']) ? trim($payload['department']) : '';
    $notes = isset($payload['notes']) ? trim($payload['notes']) : '';

    if ($name === '' || $start === '' || $end === '') {
      http_response_code(400);
      return json_encode(['success' => false, 'message' => 'Missing required fields']);
    }

    // Fetch active employees (optionally filter by department)
    $empSql = "SELECT employee_id FROM tblemployees WHERE status = 'active'";
    if ($department !== '') { $empSql .= " AND department = :dept"; }
    $empStmt = $conn->prepare($empSql);
    if ($department !== '') { $empStmt->bindValue(':dept', $department); }
    $empStmt->execute();
    $employees = $empStmt->fetchAll(PDO::FETCH_COLUMN) ?: [];
    $totalEmployees = count($employees);

    // Determine user creating the batch, if available
    $generatedBy = null;
    if (isset($_SESSION['user_id'])) { $generatedBy = (int)$_SESSION['user_id']; }

    // Create batch
    $ins = $conn->prepare("INSERT INTO tblpayroll_by_batch (batch_name, payroll_period_start, payroll_period_end, department, total_employees, total_amount, status, notes, generated_by)
                           VALUES (:name, :start, :end, :dept, :total_employees, 0.00, 'processing', :notes, :generated_by)");
    $ins->bindValue(':name', $name);
    $ins->bindValue(':start', $start);
    $ins->bindValue(':end', $end);
    if ($department !== '') { $ins->bindValue(':dept', $department); } else { $ins->bindValue(':dept', null, PDO::PARAM_NULL); }
    $ins->bindValue(':total_employees', $totalEmployees, PDO::PARAM_INT);
    if ($notes !== '') { $ins->bindValue(':notes', $notes); } else { $ins->bindValue(':notes', null, PDO::PARAM_NULL); }
    if ($generatedBy !== null) { $ins->bindValue(':generated_by', $generatedBy, PDO::PARAM_INT); } else { $ins->bindValue(':generated_by', null, PDO::PARAM_NULL); }

    try {
      $conn->beginTransaction();
      $ok = $ins->execute();
      if (!$ok) {
        $errorInfo = $ins->errorInfo();
        $conn->rollBack();
        return json_encode(['success' => false, 'message' => 'Database error: ' . $errorInfo[2]]);
      }
      $batchId = (int)$conn->lastInsertId();

      // Prepare per-employee insert
      $insEmp = $conn->prepare("INSERT INTO tblpayroll_batch_employees (batch_id, employee_id, basic_salary, overtime_pay, deductions, net_pay, status)
                                VALUES (:batch_id, :employee_id, :basic_salary, :overtime_pay, :deductions, :net_pay, 'pending')");
      // Also insert to main payroll table so employees see active payslips
      $insPay = $conn->prepare("INSERT INTO tblpayroll (employee_id, payroll_period_start, payroll_period_end, basic_salary, total_overtime_hours, overtime_pay, deductions, net_pay)
                                VALUES (:employee_id, :start, :end, :basic_salary, :total_overtime_hours, :overtime_pay, :deductions, :net_pay)");
      
      $sumNet = 0.0;
      foreach ($employees as $eid) {
        $eid = (int)$eid; if (!$eid) continue;
        // Get employee salary info
        $selEmp = $conn->prepare('SELECT basic_salary, salary_rate_type FROM tblemployees WHERE employee_id = :id');
        $selEmp->bindValue(':id', $eid, PDO::PARAM_INT);
        $selEmp->execute();
        $emp = $selEmp->fetch(PDO::FETCH_ASSOC);
        if (!$emp) continue;
        $basic = (float)$emp['basic_salary'];
        $rateType = isset($emp['salary_rate_type']) ? strtolower(trim($emp['salary_rate_type'])) : 'monthly';

        // Attendance-based deductions and overtime (reuse payroll logic helper)
        $att = calculateAttendanceDeductionsForPayroll($conn, $eid, $start, $end);
        $otPay = isset($att['total_overtime_pay']) ? (float)$att['total_overtime_pay'] : 0.0;

        // Compute base pay for the selected period
        $basePay = 0.0;
        if ($rateType === 'monthly') {
          try {
            $dtStart = new DateTime($start);
            $dtEnd = new DateTime($end);
            $dtStart->setTime(0,0,0);
            $dtEnd->setTime(0,0,0);
            $sameDay = ($dtStart->format('d') === $dtEnd->format('d')) && ($dtEnd > $dtStart);
            if ($sameDay) {
              $diff = $dtStart->diff($dtEnd);
              $months = ($diff->y * 12) + $diff->m; if ($months <= 0) { $months = 1; }
              $basePay = $basic * $months;
            } else {
              $days = max(0, (int)round(($dtEnd->getTimestamp() - $dtStart->getTimestamp()) / 86400));
              if ($days <= 0) { $days = 1; }
              $basePay = ($basic / 30.0) * $days;
            }
          } catch (Exception $e) { $basePay = $basic; }
        } else {
          // daily or hourly: from helper output
          $basePay = (isset($att['daily_wage']) ? (float)$att['daily_wage'] : 0.0) * (isset($att['total_work_days']) ? (int)$att['total_work_days'] : 0);
        }

        $gross = $basePay + $otPay;
        $bk = computeDeductionsBreakdown($gross);
        $dedTotal = (isset($bk['total']) ? (float)$bk['total'] : 0.0) + (isset($att['total_deductions']) ? (float)$att['total_deductions'] : 0.0);
        $net = $gross - $dedTotal;

        // Insert detail row
        $insEmp->bindValue(':batch_id', $batchId, PDO::PARAM_INT);
        $insEmp->bindValue(':employee_id', $eid, PDO::PARAM_INT);
        $insEmp->bindValue(':basic_salary', $basic);
        $insEmp->bindValue(':overtime_pay', $otPay);
        $insEmp->bindValue(':deductions', $dedTotal);
        $insEmp->bindValue(':net_pay', $net);
        try { $insEmp->execute(); } catch (Exception $e) { /* skip individual failures */ }
        $sumNet += $net;

        // Mirror into tblpayroll for employee visibility
        try {
          $insPay->bindValue(':employee_id', $eid, PDO::PARAM_INT);
          $insPay->bindValue(':start', $start);
          $insPay->bindValue(':end', $end);
          $insPay->bindValue(':basic_salary', $basic);
          $insPay->bindValue(':total_overtime_hours', isset($att['total_overtime_hours']) ? (float)$att['total_overtime_hours'] : 0.0);
          $insPay->bindValue(':overtime_pay', $otPay);
          $insPay->bindValue(':deductions', $dedTotal);
          $insPay->bindValue(':net_pay', $net);
          $insPay->execute();
          
          // Notify employee that their payroll has been processed in batch
          $processorName = '';
          if ($generatedBy) {
            $processorName = getUserName($conn, $generatedBy);
          }
          
          // Get employee name for the message
          $empName = 'Employee';
          try {
            $empStmt = $conn->prepare('SELECT first_name, last_name FROM tblemployees WHERE employee_id = :emp_id LIMIT 1');
            $empStmt->bindParam(':emp_id', $eid, PDO::PARAM_INT);
            $empStmt->execute();
            $empRow = $empStmt->fetch(PDO::FETCH_ASSOC);
            if ($empRow) {
              $empName = trim($empRow['first_name'] . ' ' . $empRow['last_name']);
              if (empty($empName)) {
                $empName = 'Employee';
              }
            }
          } catch (Exception $e) { /* ignore errors */ }
          
          // Get department info for the message
          $deptInfo = 'payroll';
          if ($department !== '') {
            $deptInfo = $department . ' department payroll';
          }
          
          $empMsg = $processorName ? 
            $processorName . ' processed ' . $deptInfo . ' for the period ' . $start . ' → ' . $end . ' (Batch: ' . $name . ')' :
            $deptInfo . ' has been processed for the period ' . $start . ' → ' . $end . ' (Batch: ' . $name . ')';
          $empIns = $conn->prepare('INSERT INTO tblnotifications(employee_id, message, type, actor_user_id) VALUES(:eid, :msg, :type, :actor)');
          $empIns->bindValue(':eid', $eid, PDO::PARAM_INT);
          $empIns->bindValue(':msg', $empMsg);
          $empIns->bindValue(':type', 'payroll_processed');
          if ($generatedBy !== null) { $empIns->bindValue(':actor', $generatedBy, PDO::PARAM_INT); }
          else { $empIns->bindValue(':actor', null, PDO::PARAM_NULL); }
          try { $empIns->execute(); } catch (Exception $e) { /* ignore individual notification errors */ }
          
        } catch (Exception $e) { /* ignore payroll insert errors for individual employees */ }

              }

      // Update batch totals and status
      $upd = $conn->prepare("UPDATE tblpayroll_by_batch SET total_employees = :te, total_amount = :ta WHERE batch_id = :id");
      $upd->bindValue(':te', $totalEmployees, PDO::PARAM_INT);
      $upd->bindValue(':ta', round($sumNet, 2));
      $upd->bindValue(':id', $batchId, PDO::PARAM_INT);
      $upd->execute();

      $conn->commit();
      // Notify admins that an HR generated a payroll batch
      try {
        if (isset($_SESSION['role']) && strtolower((string)$_SESSION['role']) === 'hr') {
          $actor = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
          $processorName = '';
          if ($actor) {
            $processorName = getUserName($conn, $actor);
          }
          
          // Get department info if available
          $deptInfo = '';
          if ($department !== '') {
            $deptInfo = $department . ' department';
          }
          
          $msg = $processorName && !empty($deptInfo) ? 
            $processorName . ' created ' . $deptInfo . ' payroll for the period ' . $start . ' → ' . $end . ' (Batch: ' . $name . ')' :
            ($processorName ? 
              $processorName . ' created payroll batch: ' . $name . ' for the period ' . $start . ' → ' . $end :
              'HR created payroll batch: ' . $name . ' for the period ' . $start . ' → ' . $end);
          notifyAdmins($conn, 'payroll_batch_created', $msg, $actor);
        }
        
        // If an admin created the payroll batch, notify HR users
        if (isset($_SESSION['role']) && strtolower((string)$_SESSION['role']) === 'admin') {
          $actor = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
          $processorName = '';
          if ($actor) {
            $processorName = getUserName($conn, $actor);
          }
          
          // Get department info if available
          $deptInfo = '';
          if ($department !== '') {
            $deptInfo = $department . ' department';
          }
          
          $msg = $processorName && !empty($deptInfo) ? 
            $processorName . ' created ' . $deptInfo . ' payroll for the period ' . $start . ' → ' . $end . ' (Batch: ' . $name . ')' :
            ($processorName ? 
              $processorName . ' created payroll batch: ' . $name . ' for the period ' . $start . ' → ' . $end :
              'Admin created payroll batch: ' . $name . ' for the period ' . $start . ' → ' . $end);
          
          // Notify HR users
          notifyHR($conn, 'payroll_batch_created', $msg, $actor);
        }
      } catch (Exception $e) { /* ignore notification errors */ }
      return json_encode(['success' => true, 'batch_id' => $batchId, 'total_employees' => $totalEmployees, 'total_amount' => round($sumNet, 2)]);
    } catch (Exception $e) {
      if ($conn->inTransaction()) { try { $conn->rollBack(); } catch (Exception $e2) {} }
      return json_encode(['success' => false, 'message' => 'Exception: ' . $e->getMessage()]);
    }
  }

  /**
   * List payroll batches
   * Optional filters: search (batch_name or batch_id), status, date (YYYY-MM-DD)
   */
  function setPayrollBatchStatus($conn){
    $payload = [];
    if (isset($_POST['json'])) { $payload = json_decode($_POST['json'], true) ?: []; }
    else { $payload = $_POST; }
    $id = isset($payload['batch_id']) ? (int)$payload['batch_id'] : 0;
    $status = isset($payload['status']) ? strtolower(trim($payload['status'])) : '';
    $allowed = ['pending','processing','completed','failed'];
    if (!$id || !in_array($status, $allowed)) {
      http_response_code(400);
      return json_encode(['success' => false, 'message' => 'Invalid parameters']);
    }
    $stmt = $conn->prepare("UPDATE tblpayroll_by_batch SET status = :status, updated_at = NOW() WHERE batch_id = :id");
    $stmt->bindValue(':status', $status);
    $stmt->bindValue(':id', $id, PDO::PARAM_INT);
    $ok = $stmt->execute();

    // On completion, backfill tblpayroll rows for employee dashboard if missing
    if ($ok && $status === 'completed') {
      try {
        $selBatch = $conn->prepare("SELECT payroll_period_start, payroll_period_end FROM tblpayroll_by_batch WHERE batch_id = :id LIMIT 1");
        $selBatch->bindValue(':id', $id, PDO::PARAM_INT);
        $selBatch->execute();
        $b = $selBatch->fetch(PDO::FETCH_ASSOC);
        if ($b) {
          $ps = $b['payroll_period_start'];
          $pe = $b['payroll_period_end'];
          $selEmp = $conn->prepare("SELECT be.employee_id, be.basic_salary, be.overtime_pay, be.deductions, be.net_pay FROM tblpayroll_batch_employees be WHERE be.batch_id = :id");
          $selEmp->bindValue(':id', $id, PDO::PARAM_INT);
          $selEmp->execute();
          $rows = $selEmp->fetchAll(PDO::FETCH_ASSOC) ?: [];
          $exists = $conn->prepare("SELECT COUNT(*) FROM tblpayroll WHERE employee_id = :eid AND payroll_period_start = :ps AND payroll_period_end = :pe");
          $insPay = $conn->prepare("INSERT INTO tblpayroll (employee_id, payroll_period_start, payroll_period_end, basic_salary, total_overtime_hours, overtime_pay, deductions, net_pay) VALUES (:employee_id, :start, :end, :basic_salary, :total_overtime_hours, :overtime_pay, :deductions, :net_pay)");
          foreach ($rows as $r) {
            $eid = (int)$r['employee_id']; if (!$eid) continue;
            $exists->bindValue(':eid', $eid, PDO::PARAM_INT);
            $exists->bindValue(':ps', $ps);
            $exists->bindValue(':pe', $pe);
            $exists->execute();
            if ((int)$exists->fetchColumn() > 0) continue;
            try {
              $insPay->bindValue(':employee_id', $eid, PDO::PARAM_INT);
              $insPay->bindValue(':start', $ps);
              $insPay->bindValue(':end', $pe);
              $insPay->bindValue(':basic_salary', (float)$r['basic_salary']);
              $insPay->bindValue(':total_overtime_hours', 0.0);
              $insPay->bindValue(':overtime_pay', (float)$r['overtime_pay']);
              $insPay->bindValue(':deductions', (float)$r['deductions']);
              $insPay->bindValue(':net_pay', (float)$r['net_pay']);
              $insPay->execute();
            } catch (Exception $e2) { /* ignore individual record errors */ }
          }
        }
      } catch (Exception $e) { /* ignore backfill errors */ }
      // Mark batch employees' payroll rows as PAID so employees can download payslips
      try {
        $actor = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
        $updPay = $conn->prepare("UPDATE tblpayroll p
          INNER JOIN tblpayroll_by_batch bch ON bch.payroll_period_start = p.payroll_period_start AND bch.payroll_period_end = p.payroll_period_end
          INNER JOIN tblpayroll_batch_employees be ON be.batch_id = bch.batch_id AND be.employee_id = p.employee_id
          SET p.status = 'paid',
              p.paid_at = COALESCE(p.paid_at, NOW()),
              p.paid_by = COALESCE(p.paid_by, :actor)
          WHERE bch.batch_id = :id");
        $updPay->bindValue(':id', $id, PDO::PARAM_INT);
        if ($actor !== null) { $updPay->bindValue(':actor', $actor, PDO::PARAM_INT); }
        else { $updPay->bindValue(':actor', null, PDO::PARAM_NULL); }
        $updPay->execute();
        
        // Notify employees that their payroll has been paid
        $selBatchInfo = $conn->prepare("SELECT payroll_period_start, payroll_period_end FROM tblpayroll_by_batch WHERE batch_id = :id LIMIT 1");
        $selBatchInfo->bindValue(':id', $id, PDO::PARAM_INT);
        $selBatchInfo->execute();
        $batchInfo = $selBatchInfo->fetch(PDO::FETCH_ASSOC);
        if ($batchInfo) {
          $period = $batchInfo['payroll_period_start'] . ' → ' . $batchInfo['payroll_period_end'];
          $selEmployees = $conn->prepare("SELECT be.employee_id FROM tblpayroll_batch_employees be WHERE be.batch_id = :id");
          $selEmployees->bindValue(':id', $id, PDO::PARAM_INT);
          $selEmployees->execute();
          $employees = $selEmployees->fetchAll(PDO::FETCH_COLUMN);
          
          foreach ($employees as $empId) {
            $processorName = '';
            if ($actor !== null) {
              $processorName = getUserName($conn, $actor);
            }
            
            // Get employee name for the message
            $empName = 'Employee';
            try {
              $empStmt = $conn->prepare('SELECT first_name, last_name FROM tblemployees WHERE employee_id = :emp_id LIMIT 1');
              $empStmt->bindParam(':emp_id', $empId, PDO::PARAM_INT);
              $empStmt->execute();
              $empRow = $empStmt->fetch(PDO::FETCH_ASSOC);
              if ($empRow) {
                $empName = trim($empRow['first_name'] . ' ' . $empRow['last_name']);
                if (empty($empName)) {
                  $empName = 'Employee';
                }
              }
            } catch (Exception $e) { /* ignore errors */ }
            
            $empMsg = $processorName ? 
              $processorName . ' paid ' . $empName . '’s payslip (' . $period . ')' :
              $empName . '’s payslip has been paid (' . $period . ')';
            $empIns = $conn->prepare('INSERT INTO tblnotifications(employee_id, message, type, actor_user_id) VALUES(:eid, :msg, :type, :actor)');
            $empIns->bindValue(':eid', $empId, PDO::PARAM_INT);
            $empIns->bindValue(':msg', $empMsg);
            $empIns->bindValue(':type', 'payslip_paid');
            if ($actor !== null) { $empIns->bindValue(':actor', $actor, PDO::PARAM_INT); }
            else { $empIns->bindValue(':actor', null, PDO::PARAM_NULL); }
            try { $empIns->execute(); } catch (Exception $e) { /* ignore individual notification errors */ }
          }
          
          // If an admin completed the payroll batch, notify HR users
          if (isset($_SESSION['role']) && strtolower((string)$_SESSION['role']) === 'admin') {
            $selBatchName = $conn->prepare("SELECT batch_name, department FROM tblpayroll_by_batch WHERE batch_id = :id LIMIT 1");
            $selBatchName->bindValue(':id', $id, PDO::PARAM_INT);
            $selBatchName->execute();
            $batchData = $selBatchName->fetch(PDO::FETCH_ASSOC);
            
            if ($batchData) {
              $batchName = $batchData['batch_name'];
              $deptInfo = '';
              if (!empty($batchData['department'])) {
                $deptInfo = $batchData['department'] . ' department';
              }
              
              $processorName = '';
              if ($actor !== null) {
                $processorName = getUserName($conn, $actor);
              }
              
              $msg = $processorName && !empty($deptInfo) ? 
                $processorName . ' processed ' . $deptInfo . ' payroll for the period ' . $period . ' (Batch: ' . $batchName . ')' :
                ($processorName ? 
                  $processorName . ' completed payroll batch: ' . $batchName . ' for the period ' . $period :
                  'Admin completed payroll batch: ' . $batchName . ' for the period ' . $period);
              
              // Notify HR users
              notifyHR($conn, 'payroll_batch_completed', $msg, $actor);
            }
          }
        }
        
      } catch (Exception $e3) { /* ignore marking errors */ }
    }

    // If batch is set back to processing, revert payroll rows to processed to disable downloads
    if ($ok && $status === 'processing') {
      try {
        $updPay = $conn->prepare("UPDATE tblpayroll p
          INNER JOIN tblpayroll_by_batch bch ON bch.payroll_period_start = p.payroll_period_start AND bch.payroll_period_end = p.payroll_period_end
          INNER JOIN tblpayroll_batch_employees be ON be.batch_id = bch.batch_id AND be.employee_id = p.employee_id
          SET p.status = 'processed',
              p.paid_at = NULL,
              p.paid_by = NULL
          WHERE bch.batch_id = :id");
        $updPay->bindValue(':id', $id, PDO::PARAM_INT);
        $updPay->execute();
      } catch (Exception $e4) { /* ignore revert errors */ }
    }

    return json_encode(['success' => $ok]);
  }

  
  function updatePayrollBatch($conn){
    $payload = [];
    if (isset($_POST['json'])) { $payload = json_decode($_POST['json'], true) ?: []; }
    else { $payload = $_POST; }
    $id = isset($payload['batch_id']) ? (int)$payload['batch_id'] : 0;
    if (!$id) { http_response_code(400); return json_encode(['success' => false, 'message' => 'Missing batch_id']); }

    $fields = [];
    $params = [ ':id' => $id ];
    if (isset($payload['batch_name'])) { $fields[] = 'batch_name = :name'; $params[':name'] = trim($payload['batch_name']); }
    if (isset($payload['payroll_period_start']) || isset($payload['period_start'])) {
      $fields[] = 'payroll_period_start = :ps';
      $params[':ps'] = isset($payload['payroll_period_start']) ? $payload['payroll_period_start'] : $payload['period_start'];
    }
    if (isset($payload['payroll_period_end']) || isset($payload['period_end'])) {
      $fields[] = 'payroll_period_end = :pe';
      $params[':pe'] = isset($payload['payroll_period_end']) ? $payload['payroll_period_end'] : $payload['period_end'];
    }
    if (array_key_exists('department', $payload)) {
      if ($payload['department'] === '' || is_null($payload['department'])) {
        $fields[] = 'department = NULL';
      } else {
        $fields[] = 'department = :dept';
        $params[':dept'] = trim($payload['department']);
      }
    }
    if (empty($fields)) {
      return json_encode(['success' => true, 'message' => 'No changes']);
    }
    $sql = 'UPDATE tblpayroll_by_batch SET ' . implode(', ', $fields) . ', updated_at = NOW() WHERE batch_id = :id';
    $stmt = $conn->prepare($sql);
    foreach ($params as $k => $v) {
      $type = PDO::PARAM_STR;
      if ($k === ':id') $type = PDO::PARAM_INT;
      $stmt->bindValue($k, $v, $type);
    }
    $ok = $stmt->execute();
    return json_encode(['success' => $ok]);
  }

  function listPayrollBatches($conn){
    $sql = "SELECT * FROM tblpayroll_by_batch WHERE 1=1";
    $params = [];

    if (!empty($_GET['status'])) {
      $sql .= " AND status = :status";
      $params[':status'] = $_GET['status'];
    }
    if (!empty($_GET['date'])) {
      // match by created_at date part
      $sql .= " AND DATE(created_at) = :cdate";
      $params[':cdate'] = $_GET['date'];
    }
    if (!empty($_GET['search'])) {
      $search = trim($_GET['search']);
      if (ctype_digit($search)) {
        $sql .= " AND (batch_id = :bid OR batch_name LIKE :s)";
        $params[':bid'] = (int)$search;
        $params[':s'] = '%' . $search . '%';
      } else {
        $sql .= " AND batch_name LIKE :s";
        $params[':s'] = '%' . $search . '%';
      }
    }

    $sql .= " ORDER BY created_at DESC, batch_id DESC";
    $stmt = $conn->prepare($sql);
    foreach ($params as $k => $v) { $stmt->bindValue($k, $v); }
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    return json_encode($rows);
  }
/**
   * Get a single payroll batch by ID
   */
  function getPayrollBatch($conn){
    $id = isset($_GET['batch_id']) ? (int)$_GET['batch_id'] : 0;
    if (!$id) { http_response_code(400); return json_encode(['success' => false, 'message' => 'Missing batch_id']); }
    $stmt = $conn->prepare("SELECT * FROM tblpayroll_by_batch WHERE batch_id = :id LIMIT 1");
    $stmt->bindValue(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) { http_response_code(404); return json_encode(['success' => false, 'message' => 'Batch not found']); }
    return json_encode(['success' => true, 'batch' => $row]);
  }

  /**
   * List employees included in a payroll batch
   */
  function listPayrollBatchEmployees($conn){
    $id = isset($_GET['batch_id']) ? (int)$_GET['batch_id'] : 0;
    if (!$id) { http_response_code(400); return json_encode([]); }
    $sql = "SELECT be.*, e.first_name, e.last_name, e.department, e.position
            FROM tblpayroll_batch_employees be
            INNER JOIN tblemployees e ON e.employee_id = be.employee_id
            WHERE be.batch_id = :id
            ORDER BY e.last_name, e.first_name";
    $stmt = $conn->prepare($sql);
    $stmt->bindValue(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    return json_encode($rows);
  }
?>
