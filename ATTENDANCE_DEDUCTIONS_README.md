# Attendance Deductions System

This document describes the implementation of the attendance deductions system for late, absent, and undertime calculations in the payroll system.

## Overview

The attendance deductions system implements the exact formulas you provided for calculating deductions based on:
- **Late arrivals** - Deductions for arriving after scheduled start time
- **Undertime** - Deductions for leaving before scheduled end time  
- **Absences** - Full or partial day deductions
- **Overtime** - Additional pay for working beyond scheduled hours

## Formulas Implemented

### 1. Late Deduction Formula
```
Net = DailyWage − (DailyWage / PaidHours / 60) × LateMinutes
```

**Example:**
- Daily wage: ₱250
- Work schedule: 8:00 AM–8:00 PM (8 paid hours, 1-hour lunch)
- Time-in: 8:15 AM (15 minutes late)
- Hourly rate: ₱250 ÷ 8 = ₱31.25/hr
- Per-minute rate: ₱31.25 ÷ 60 = ₱0.520833/min
- Late deduction: 15 × ₱0.520833 = ₱7.8125
- Net for the day: ₱250 − ₱7.8125 = ₱242.19

### 2. Undertime Deduction Formula
```
Net = DailyWage − (DailyWage / PaidHours / 60) × UndertimeMinutes
```

**Example:**
- Daily wage: ₱250
- Work schedule: 8:00 AM–8:00 PM (8 paid hours, 1-hour lunch)
- Undertime: Leaves 30 minutes early
- Undertime deduction: 30 × ₱0.520833 = ₱15.625
- Net for the day: ₱250 − ₱15.625 = ₱234.38

### 3. Overtime Pay Formula
```
Net = DailyWage + (DailyWage / PaidHours / 60) × OTMinutes × OTMultiplier
```

**Example:**
- Daily wage: ₱250
- Work schedule: 8:00 AM–8:00 PM (8 paid hours, 1-hour lunch)
- Overtime: Works 1 hour extra
- OT rate (125%): ₱0.520833 × 1.25 = ₱0.651041/min
- Overtime pay: 60 × ₱0.651041 = ₱39.0625
- Net for the day: ₱250 + ₱39.0625 = ₱289.06

### 4. Absent Deduction Formula
```
Net = DailyWage − (DailyWage / PaidHours / 60) × AbsentMinutes
```

**Example:**
- Daily wage: ₱250
- Work schedule: 8:00 AM–8:00 PM (8 paid hours, 1-hour lunch)
- Absent: Full day (no work rendered)
- Absent minutes: 8 hrs × 60 = 480 minutes
- Absent deduction: 480 × ₱0.520833 = ₱250.00
- Net for the day: ₱250 − ₱250 = ₱0.00

## System Configuration

The system uses configurable settings stored in the `system_settings` table:

| Setting Key | Description | Default Value |
|-------------|-------------|---------------|
| `work_hours_per_day` | Total work hours per day | 8 |
| `lunch_hours_per_day` | Unpaid lunch hours | 1 |
| `grace_period_minutes` | Grace period for late arrivals | 15 |
| `rounding_interval_minutes` | Rounding interval for time calculations | 15 |
| `overtime_multiplier` | Overtime pay multiplier | 1.25 |
| `late_deduction_enabled` | Enable late deductions | 1 |
| `undertime_deduction_enabled` | Enable undertime deductions | 1 |
| `absent_deduction_enabled` | Enable absent deductions | 1 |

## Files Added/Modified

### New Files
1. **`api/attendance-deductions.php`** - Main API for attendance deductions
2. **`js/modules/attendance-deductions.js`** - Frontend JavaScript module
3. **`attendance-deductions-demo.html`** - Demo page showcasing the system
4. **`ATTENDANCE_DEDUCTIONS_README.md`** - This documentation file

### Modified Files
1. **`database.sql`** - Added new system settings
2. **`api/payroll.php`** - Integrated attendance deductions into payroll generation

## API Endpoints

### 1. Get System Settings
```
GET api/attendance-deductions.php?operation=getSystemSettings
```

**Response:**
```json
{
  "work_hours_per_day": "8",
  "lunch_hours_per_day": "1",
  "grace_period_minutes": "15",
  "rounding_interval_minutes": "15",
  "overtime_multiplier": "1.25",
  "late_deduction_enabled": "1",
  "undertime_deduction_enabled": "1",
  "absent_deduction_enabled": "1"
}
```

### 2. Update System Settings
```
POST api/attendance-deductions.php
operation=updateSystemSettings
json={"work_hours_per_day": 9, "lunch_hours_per_day": 1}
```

### 3. Calculate Deductions
```
POST api/attendance-deductions.php
operation=calculateDeductions
json={"employee_id": 1, "start_date": "2025-08-01", "end_date": "2025-08-31"}
```

### 4. Calculate Payroll Deductions
```
POST api/attendance-deductions.php
operation=calculatePayrollDeductions
json={"employee_id": 1, "start_date": "2025-08-01", "end_date": "2025-08-31"}
```

## Usage Examples

### 1. Frontend Integration

```javascript
// Initialize the module
const attendanceDeductions = new AttendanceDeductions();

// Calculate deductions for an employee
const results = await attendanceDeductions.calculateDeductions(
    employeeId, 
    startDate, 
    endDate
);

// Display results in a table
attendanceDeductions.createDeductionsTable(results, 'containerId');

// Update system settings
const success = await attendanceDeductions.updateSystemSettings({
    work_hours_per_day: 9,
    grace_period_minutes: 20
});
```

### 2. Manual Calculations

```javascript
// Calculate deductions manually
const results = attendanceDeductions.calculateDeductionsManually(
    250,    // daily wage
    8,      // work hours
    1,      // lunch hours
    15,     // late minutes
    30,     // undertime minutes
    0,      // absent hours
    60      // overtime minutes
);

console.log(results.net_pay); // Net pay for the day
```

### 3. Payroll Integration

The system automatically integrates with the existing payroll generation:

```php
// In generatePayroll function
$attendanceDeductions = calculateAttendanceDeductionsForPayroll($conn, $empId, $start, $end);
$deductionsTotal = $break['total'] + $attendanceDeductions['total_deductions'];
```

## Features

### 1. Configurable Settings
- Work hours per day
- Lunch hours (unpaid)
- Grace period for late arrivals
- Rounding intervals for time calculations
- Overtime multipliers
- Enable/disable specific deduction types

### 2. Automatic Calculations
- Late deductions based on time-in records
- Undertime deductions based on time-out records
- Absent deductions for full/partial days
- Overtime pay for approved overtime requests
- Integration with existing overtime/undertime request system

### 3. Comprehensive Reporting
- Daily breakdown of deductions and earnings
- Summary totals for the period
- Formula explanations and rates used
- Detailed attendance analysis

### 4. Grace Periods and Rounding
- Configurable grace period for late arrivals
- Time rounding to specified intervals (e.g., 15 minutes)
- Prevents minor delays from triggering deductions

## Database Schema Changes

### New System Settings
```sql
INSERT INTO system_settings (setting_key, setting_value) VALUES
('work_hours_per_day', '8'),
('lunch_hours_per_day', '1'),
('grace_period_minutes', '15'),
('rounding_interval_minutes', '15'),
('late_deduction_enabled', '1'),
('undertime_deduction_enabled', '1'),
('absent_deduction_enabled', '1');
```

## Testing

1. **Demo Page**: Open `attendance-deductions-demo.html` to test the system
2. **Manual Calculator**: Use the form to test different scenarios
3. **API Testing**: Test the endpoints with real employee data
4. **Payroll Integration**: Generate payroll to see deductions applied

## Error Handling

The system includes comprehensive error handling:
- Missing employee data
- Invalid date ranges
- Database connection issues
- Configuration errors
- Graceful fallbacks to default values

## Performance Considerations

- Efficient database queries with proper indexing
- Caching of system settings
- Batch processing for multiple employees
- Optimized calculations for large date ranges

## Security

- Input validation and sanitization
- SQL injection prevention with prepared statements
- Access control through existing user authentication
- Audit logging for configuration changes

## Future Enhancements

1. **Multiple Shift Support**: Different schedules for different employees
2. **Holiday and Leave Integration**: Consider paid leave in calculations
3. **Advanced Rounding Rules**: Company-specific rounding policies
4. **Bulk Operations**: Process multiple employees simultaneously
5. **Export Functionality**: CSV/PDF reports of deductions
6. **Mobile Support**: Mobile-friendly interface for managers

## Support

For questions or issues with the attendance deductions system:
1. Check the demo page for examples
2. Review the API documentation
3. Test with sample data
4. Check system settings configuration
5. Review error logs for debugging

## Conclusion

The attendance deductions system provides a robust, configurable solution for calculating late, absent, and undertime deductions using the exact formulas you specified. It integrates seamlessly with the existing payroll system and provides comprehensive reporting and management capabilities.
