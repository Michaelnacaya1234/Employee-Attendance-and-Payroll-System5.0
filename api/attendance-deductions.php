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
    case 'calculateDeductions':
      echo calculateDeductions($conn);
      break;
    case 'getSystemSettings':
      echo getSystemSettings($conn);
      break;
    case 'updateSystemSettings':
      echo updateSystemSettings($conn);
      break;
    case 'calculatePayrollDeductions':
      echo calculatePayrollDeductions($conn);
      break;
    default:
      echo json_encode([]);
  }

  /**
   * RETRIEVE ATTENDANCE DEDUCTION SYSTEM SETTINGS
   * Fetches configuration settings for attendance calculations
   * Returns work hours, grace periods, and deduction rules
   */
  function getSystemSettings($conn) {
    $sql = "SELECT setting_key, setting_value FROM tblsystem_settings 
            WHERE setting_key IN (
              'work_hours_per_day', 'lunch_hours_per_day', 'grace_period_minutes', 
              'rounding_interval_minutes', 'overtime_multiplier', 'late_deduction_enabled',
              'undertime_deduction_enabled', 'absent_deduction_enabled', 'paid_hours_per_day',
              'use_exact_minutes_for_late', 'use_override_daily_wage', 'override_daily_wage'
            )";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $settings = [];
    foreach ($rows as $row) {
      $settings[$row['setting_key']] = $row['setting_value'];
    }
    
    return json_encode($settings);
  }

  /**
   * UPDATE ATTENDANCE DEDUCTION SETTINGS
   * Modifies system configuration for attendance calculations
   * Handles bulk updates of deduction-related settings
   */
  function updateSystemSettings($conn) {
    $data = json_decode($_POST['json'], true);
    $success = true;
    
    foreach ($data as $key => $value) {
      $sql = "INSERT INTO tblsystem_settings (setting_key, setting_value) 
              VALUES (:key, :value) 
              ON DUPLICATE KEY UPDATE setting_value = :value";
      $stmt = $conn->prepare($sql);
      $stmt->bindParam(':key', $key);
      $stmt->bindParam(':value', $value);
      if (!$stmt->execute()) {
        $success = false;
      }
    }
    
    return json_encode(['success' => $success]);
  }

  /**
   * CALCULATE ATTENDANCE DEDUCTIONS FOR EMPLOYEE
   * Computes deductions based on attendance, overtime, and undertime
   * Returns detailed breakdown of calculations and penalties
   */
  function calculateDeductions($conn) {
    $data = json_decode($_POST['json'], true);
    $employeeId = isset($data['employee_id']) ? (int)$data['employee_id'] : 0;
    $startDate = isset($data['start_date']) ? $data['start_date'] : '';
    $endDate = isset($data['end_date']) ? $data['end_date'] : '';
    // Expose selected period globally for downstream calculations
    $GLOBALS['__period_start'] = $startDate;
    $GLOBALS['__period_end'] = $endDate;
    
    if (!$employeeId || !$startDate || !$endDate) {
      return json_encode(['error' => 'Missing required parameters']);
    }
    
    // Get employee salary information
    $stmt = $conn->prepare("SELECT basic_salary, salary_rate_type FROM tblemployees WHERE employee_id = :id");
    $stmt->bindParam(':id', $employeeId, PDO::PARAM_INT);
    $stmt->execute();
    $employee = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$employee) {
      return json_encode(['error' => 'Employee not found']);
    }
    
    // Get system settings
    $settings = getSystemSettingsArray($conn);
    
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
    
    // Calculate deductions
    $results = calculateAttendanceDeductions(
      $employee, 
      $attendance, 
      $overtime, 
      $undertime, 
      $settings
    );
    
    return json_encode($results);
  }

  /**
   * CALCULATE PAYROLL PERIOD DEDUCTIONS
   * Computes comprehensive payroll deductions for specific period
   * Integrates all attendance-related calculations for payroll
   */
  function calculatePayrollDeductions($conn) {
    $data = json_decode($_POST['json'], true);
    $employeeId = isset($data['employee_id']) ? (int)$data['employee_id'] : 0;
    $startDate = isset($data['start_date']) ? $data['start_date'] : '';
    $endDate = isset($data['end_date']) ? $data['end_date'] : '';
    // Expose selected period globally for downstream calculations
    $GLOBALS['__period_start'] = $startDate;
    $GLOBALS['__period_end'] = $endDate;
    
    if (!$employeeId || !$startDate || !$endDate) {
      return json_encode(['error' => 'Missing required parameters']);
    }
    
    // Get employee salary information
    $stmt = $conn->prepare("SELECT basic_salary, salary_rate_type FROM tblemployees WHERE employee_id = :id");
    $stmt->bindParam(':id', $employeeId, PDO::PARAM_INT);
    $stmt->execute();
    $employee = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$employee) {
      return json_encode(['error' => 'Employee not found']);
    }
    
    // Get system settings
    $settings = getSystemSettingsArray($conn);
    
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
    
    // Calculate deductions
    $results = calculateAttendanceDeductions(
      $employee, 
      $attendance, 
      $overtime, 
      $undertime, 
      $settings
    );
    
    return json_encode($results);
  }

  /**
   * Helper function to get system settings as array
   */
  function getSystemSettingsArray($conn) {
    $sql = "SELECT setting_key, setting_value FROM tblsystem_settings 
            WHERE setting_key IN (
              'work_hours_per_day', 'lunch_hours_per_day', 'grace_period_minutes', 
              'rounding_interval_minutes', 'overtime_multiplier', 'late_deduction_enabled',
              'undertime_deduction_enabled', 'absent_deduction_enabled', 'paid_hours_per_day',
              'use_exact_minutes_for_late', 'use_override_daily_wage', 'override_daily_wage'
            )";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $settings = [];
    foreach ($rows as $row) {
      $settings[$row['setting_key']] = $row['setting_value'];
    }
    
    // Set default values if not found
    $defaults = [
      'work_hours_per_day' => 12,
      'lunch_hours_per_day' => 1,
      'grace_period_minutes' => 0,
      'rounding_interval_minutes' => 0,
      'overtime_multiplier' => 1.25,
      'late_deduction_enabled' => 1,
      'undertime_deduction_enabled' => 1,
      'absent_deduction_enabled' => 1,
      'paid_hours_per_day' => 12,
      'use_exact_minutes_for_late' => 1,
      'use_override_daily_wage' => 1,
      'override_daily_wage' => 0
    ];
    
    foreach ($defaults as $key => $default) {
      if (!isset($settings[$key])) {
        $settings[$key] = $default;
      }
    }
    
    return $settings;
  }

  /**
   * Main function to calculate attendance deductions
   */
  function calculateAttendanceDeductions($employee, $attendance, $overtime, $undertime, $settings) {
    $workHoursPerDay = (float)$settings['work_hours_per_day'];
    $lunchHoursPerDay = (float)$settings['lunch_hours_per_day'];
    $gracePeriodMinutes = (float)$settings['grace_period_minutes'];
    $roundingInterval = (float)$settings['rounding_interval_minutes'];
    $overtimeMultiplier = (float)$settings['overtime_multiplier'];
    $useExactLate = isset($settings['use_exact_minutes_for_late']) ? (bool)$settings['use_exact_minutes_for_late'] : false;
    // Selected period passed via settings or globals
    $startDateSel = isset($settings['__start_date']) ? $settings['__start_date'] : (isset($GLOBALS['__period_start']) ? $GLOBALS['__period_start'] : null);
    $endDateSel = isset($settings['__end_date']) ? $settings['__end_date'] : (isset($GLOBALS['__period_end']) ? $GLOBALS['__period_end'] : null);
    
    $lateDeductionEnabled = (bool)$settings['late_deduction_enabled'];
    $undertimeDeductionEnabled = (bool)$settings['undertime_deduction_enabled'];
    $absentDeductionEnabled = (bool)$settings['absent_deduction_enabled'];
    
    $basicSalary = (float)$employee['basic_salary'];
    $salaryRateType = $employee['salary_rate_type'];
    
    // Convert monthly salary to daily if needed
    $dailyWage = $basicSalary;
    if ($salaryRateType === 'monthly') {
      // Using 30 days per month
      $dailyWage = $basicSalary / 30;
    } elseif ($salaryRateType === 'weekly') {
      $dailyWage = $basicSalary / 7;
    } elseif ($salaryRateType === 'hourly') {
      $dailyWage = $basicSalary * $workHoursPerDay;
    }
    // Apply override daily wage if enabled
    $useOverrideDaily = isset($settings['use_override_daily_wage']) ? (bool)$settings['use_override_daily_wage'] : false;
    $overrideDaily = isset($settings['override_daily_wage']) ? (float)$settings['override_daily_wage'] : 0;
    if ($useOverrideDaily) {
      if ($overrideDaily > 0) {
        $dailyWage = $overrideDaily;
      } else {
        // Derive per-employee daily wage from basic salary
        if ($salaryRateType === 'monthly') {
          // Use calendar days (30) to get 1000/day from 30,000/month
          $dailyWage = $basicSalary / 30;
        } elseif ($salaryRateType === 'daily') {
          $dailyWage = $basicSalary;
        } elseif ($salaryRateType === 'weekly') {
          $dailyWage = $basicSalary / 7;
        } elseif ($salaryRateType === 'hourly') {
          $dailyWage = $basicSalary * $workHoursPerDay;
        }
      }
    }
    
    $paidHours = isset($settings['paid_hours_per_day']) && (float)$settings['paid_hours_per_day'] > 0
      ? (float)$settings['paid_hours_per_day']
      : ($workHoursPerDay - $lunchHoursPerDay);
    $hourlyRate = $dailyWage / $paidHours;
    $perMinuteRate = $hourlyRate / 60;
    
    $totalLateDeduction = 0;
    $totalUndertimeDeduction = 0;
    $totalAbsentDeduction = 0;
    $totalOvertimePay = 0;
    $totalWorkDays = 0;
    $totalAbsentDays = 0;

    // Determine total period days based on selected date range (end-exclusive).
    $periodDays = $totalWorkDays;
    if ($startDateSel && $endDateSel) {
      try {
        $dtS = new DateTime($startDateSel);
        $dtE = new DateTime($endDateSel);
        $dtS->setTime(0,0,0);
        $dtE->setTime(0,0,0);
        $periodDays = max(0, (int)$dtS->diff($dtE)->days);
      } catch (Exception $e) {
        // keep default
      }
    }
    
    $dailyBreakdown = [];
    
    // Process each day
    foreach ($attendance as $record) {
      $date = $record['attendance_date'];
      $status = $record['status'];
      $timeIn = $record['time_in'];
      $timeOut = $record['time_out'];
      
      $dailyLateDeduction = 0;
      $dailyUndertimeDeduction = 0;
      $dailyOvertimePay = 0;
      $dailyAbsentDeduction = 0;
      $dailyNet = $dailyWage;
      
      if ($status === 'absent') {
        if ($absentDeductionEnabled) {
          // Prefer DB-provided absent minutes if available (absent_minutes, absent_min, absent)
          $dbAbsentMin = null;
          if (array_key_exists('absent_minutes', $record)) $dbAbsentMin = parseMinutes($record['absent_minutes']);
          if ($dbAbsentMin === null && array_key_exists('absent_min', $record)) $dbAbsentMin = parseMinutes($record['absent_min']);
          if ($dbAbsentMin === null && array_key_exists('absent', $record)) $dbAbsentMin = parseMinutes($record['absent']);
          $absentMinutes = ($dbAbsentMin !== null) ? $dbAbsentMin : ($paidHours * 60);
          $dailyAbsentDeduction = ($dailyWage / $paidHours / 60) * $absentMinutes;
          $dailyNet = $dailyWage - $dailyAbsentDeduction;
          $totalAbsentDeduction += $dailyAbsentDeduction;
          $totalAbsentDays++;
        }
      } else {
        $totalWorkDays++;
        
        // Calculate late deduction (prefer DB-provided late minutes)
        if ($lateDeductionEnabled) {
          $lateMinutes = null;
          if (array_key_exists('late_minutes', $record)) $lateMinutes = parseMinutes($record['late_minutes']);
          if ($lateMinutes === null && array_key_exists('late_min', $record)) $lateMinutes = parseMinutes($record['late_min']);
          if ($lateMinutes === null && array_key_exists('late', $record)) $lateMinutes = parseMinutes($record['late']);
          if ($lateMinutes === null && $timeIn) {
            $lateMinutes = calculateLateMinutes($timeIn, $useExactLate ? 0 : $gracePeriodMinutes, $useExactLate ? 0 : $roundingInterval);
          }
          if ($lateMinutes && $lateMinutes > 0) {
            $dailyLateDeduction = ($dailyWage / $paidHours / 60) * $lateMinutes;
            $dailyNet -= $dailyLateDeduction;
            $totalLateDeduction += $dailyLateDeduction;
          }
        }
        
        // Calculate undertime deduction (prefer DB-provided or derived from totalwork)
        if ($undertimeDeductionEnabled) {
          $undertimeMinutes = null;
          if (array_key_exists('undertime_minutes', $record)) $undertimeMinutes = parseMinutes($record['undertime_minutes']);
          if ($undertimeMinutes === null && array_key_exists('undertime_min', $record)) $undertimeMinutes = parseMinutes($record['undertime_min']);
          if ($undertimeMinutes === null && array_key_exists('undertime', $record)) $undertimeMinutes = parseMinutes($record['undertime']);
          if ($undertimeMinutes === null && array_key_exists('totalwork', $record)) {
            $tw = parseMinutes($record['totalwork']);
            if ($tw !== null) { $undertimeMinutes = max(0, ($paidHours * 60) - $tw); }
          }
          if ($undertimeMinutes === null && $timeOut) {
            $undertimeMinutes = calculateUndertimeMinutes($timeOut, $workHoursPerDay, $roundingInterval);
          }
          if ($undertimeMinutes && $undertimeMinutes > 0) {
            $dailyUndertimeDeduction = ($dailyWage / $paidHours / 60) * $undertimeMinutes;
            $dailyNet -= $dailyUndertimeDeduction;
            $totalUndertimeDeduction += $dailyUndertimeDeduction;
          }
        }
        
        // Calculate overtime pay (kept as before)
        if ($timeOut) {
          $overtimeMinutes = calculateOvertimeMinutes($timeOut, $workHoursPerDay, $roundingInterval);
          if ($overtimeMinutes > 0) {
            $dailyOvertimePay = ($dailyWage / $paidHours / 60) * $overtimeMinutes * $overtimeMultiplier;
            $dailyNet += $dailyOvertimePay;
            $totalOvertimePay += $dailyOvertimePay;
          }
        }
      }
      
      // Add approved overtime/undertime requests
      $approvedOvertime = findApprovedRequest($overtime, $date);
      $approvedUndertime = findApprovedRequest($undertime, $date);
      
      if ($approvedOvertime) {
        $otHours = (float)$approvedOvertime['hours'];
        $otPay = ($dailyWage / $paidHours / 60) * ($otHours * 60) * $overtimeMultiplier;
        $dailyOvertimePay += $otPay;
        $dailyNet += $otPay;
        $totalOvertimePay += $otPay;
      }
      
      if ($approvedUndertime) {
        $utHours = (float)$approvedUndertime['hours'];
        $utDeduction = ($dailyWage / $paidHours / 60) * ($utHours * 60);
        $dailyUndertimeDeduction += $utDeduction;
        $dailyNet -= $utDeduction;
        $totalUndertimeDeduction += $utDeduction;
      }
      
      $dailyBreakdown[] = [
        'date' => $date,
        'status' => $status,
        'daily_wage' => round($dailyWage, 2),
        'late_deduction' => round($dailyLateDeduction, 2),
        'undertime_deduction' => round($dailyUndertimeDeduction, 2),
        'overtime_pay' => round($dailyOvertimePay, 2),
        'daily_net' => round($dailyNet, 2)
      ];
    }
    
    $totalDeductions = $totalLateDeduction + $totalUndertimeDeduction + $totalAbsentDeduction;
    // Compute base pay according to salary rate and selected period
    $basePay = 0.0;
    try {
      $dtS2 = $startDateSel ? new DateTime($startDateSel) : null;
      $dtE2 = $endDateSel ? new DateTime($endDateSel) : null;
      if ($dtS2 && $dtE2) {
        $dtS2->setTime(0,0,0);
        $dtE2->setTime(0,0,0);
        if ($salaryRateType === 'monthly') {
          // Whole months if same day-of-month to same day-of-month; else pro-rate by 30
          $sameDom = ($dtS2->format('d') === $dtE2->format('d')) && ($dtE2 > $dtS2);
          if ($sameDom) {
            $diff2 = $dtS2->diff($dtE2);
            $months = ($diff2->y * 12) + $diff2->m; // whole months
            if ($months <= 0) { $months = 1; }
            $basePay = $basicSalary * $months;
          } else {
            $basePay = ($basicSalary / 30.0) * $periodDays;
          }
        } elseif ($salaryRateType === 'weekly') {
          // Whole weeks if same weekday to same weekday; else pro-rate by 7
          $sameDow = ($dtS2->format('N') === $dtE2->format('N')) && ($dtE2 > $dtS2);
          if ($sameDow) {
            $diff2 = $dtS2->diff($dtE2);
            $weeks = intdiv($diff2->days, 7);
            if ($weeks <= 0) { $weeks = 1; }
            $basePay = $basicSalary * $weeks;
          } else {
            $basePay = ($basicSalary / 7.0) * $periodDays;
          }
        } else {
          // daily or hourly-derived daily wage
          $basePay = $dailyWage * $periodDays;
        }
      } else {
        // Fallbacks if dates are missing/invalid
        if ($salaryRateType === 'monthly') { $basePay = $basicSalary; }
        elseif ($salaryRateType === 'weekly') { $basePay = $basicSalary; }
        else { $basePay = $dailyWage * $periodDays; }
      }
    } catch (Exception $e) {
      if ($salaryRateType === 'monthly') { $basePay = $basicSalary; }
      elseif ($salaryRateType === 'weekly') { $basePay = $basicSalary; }
      else { $basePay = $dailyWage * $periodDays; }
    }
    $grossPay = $basePay + $totalOvertimePay;
    $netPay = $grossPay - $totalDeductions;
    
    return [
      'summary' => [
        'total_work_days' => $periodDays,
        'actual_work_days' => $totalWorkDays,
        'total_absent_days' => $totalAbsentDays,
        'daily_wage' => round($dailyWage, 2),
        'gross_pay' => round($grossPay, 2),
        'total_late_deduction' => round($totalLateDeduction, 2),
        'total_undertime_deduction' => round($totalUndertimeDeduction, 2),
        'total_absent_deduction' => round($totalAbsentDeduction, 2),
        'total_overtime_pay' => round($totalOvertimePay, 2),
        'total_deductions' => round($totalDeductions, 2),
        'net_pay' => round($netPay, 2)
      ],
      'daily_breakdown' => $dailyBreakdown,
      'formulas_used' => [
        'hourly_rate' => round($hourlyRate, 2),
        'per_minute_rate' => round($perMinuteRate, 4),
        'paid_hours_per_day' => $paidHours,
        'overtime_multiplier' => $overtimeMultiplier
      ]
    ];
  }

  /**
   * Calculate late minutes based on time in
   */
  function calculateLateMinutes($timeIn, $gracePeriod, $roundingInterval) {
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
   * Calculate undertime minutes based on time out
   */
  function calculateUndertimeMinutes($timeOut, $workHoursPerDay, $roundingInterval) {
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

  /**
   * Calculate overtime minutes based on time out
   */
  function calculateOvertimeMinutes($timeOut, $workHoursPerDay, $roundingInterval) {
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

  /**
   * Parse minutes from various formats: integer minutes, numeric strings, or HH:MM
   */
  function parseMinutes($val) {
    if ($val === null || $val === '') return null;
    if (is_numeric($val)) return (int)round($val);
    $str = trim((string)$val);
    if (preg_match('/^(\d{1,2}):(\d{2})$/', $str, $m)) {
      return (int)$m[1] * 60 + (int)$m[2];
    }
    return null;
  }

  /**
   * Find approved request for a specific date
   */
  function findApprovedRequest($requests, $date) {
    foreach ($requests as $request) {
      if ($request['work_date'] === $date) {
        return $request;
      }
    }
    return null;
  }
?>
