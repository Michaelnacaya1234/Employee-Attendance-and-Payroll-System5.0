-- Ensure DB exists and use it
CREATE DATABASE IF NOT EXISTS dbattendance CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dbattendance;

-- Table: tbldepartments
CREATE TABLE IF NOT EXISTS tbldepartments (
    dept_id INT AUTO_INCREMENT PRIMARY KEY,
    dept_name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_departments_name (dept_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed departments (idempotent)
INSERT IGNORE INTO tbldepartments (dept_name, description) VALUES
('Finance Department', 'Handles company finances'),
('Human Resources Department', 'Oversees people operations'),
('IT Department', 'Manages company IT systems'),
('Marketing Department', 'Handles marketing and promotions'),
('Retail Operations Department', 'Manages retail store operations'),
('Warehouse Department', 'Oversees storage and inventory management');

-- Table: tbldepartment_positions
CREATE TABLE IF NOT EXISTS tbldepartment_positions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dept_id INT NOT NULL,
    position_name VARCHAR(100) NOT NULL,
    UNIQUE KEY uniq_dept_position (dept_id, position_name),
    CONSTRAINT fk_dp_department FOREIGN KEY (dept_id) REFERENCES tbldepartments(dept_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed department positions (idempotent)
-- Marketing Department (alphabetical)
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Content Writer' FROM tbldepartments WHERE dept_name = 'Marketing Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Event Coordinator' FROM tbldepartments WHERE dept_name = 'Marketing Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Marketing Manager' FROM tbldepartments WHERE dept_name = 'Marketing Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Social Media Specialist' FROM tbldepartments WHERE dept_name = 'Marketing Department';

-- Finance Department
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Accountant' FROM tbldepartments WHERE dept_name = 'Finance Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Accounts Payable Clerk' FROM tbldepartments WHERE dept_name = 'Finance Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Accounts Receivable Clerk' FROM tbldepartments WHERE dept_name = 'Finance Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Cash Handling Specialist' FROM tbldepartments WHERE dept_name = 'Finance Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Payroll Specialist' FROM tbldepartments WHERE dept_name = 'Finance Department';

-- Warehouse Department (alphabetical)
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Assistant Head' FROM tbldepartments WHERE dept_name = 'Warehouse Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Diser' FROM tbldepartments WHERE dept_name = 'Warehouse Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Head' FROM tbldepartments WHERE dept_name = 'Warehouse Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Merchandiser' FROM tbldepartments WHERE dept_name = 'Warehouse Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Warehouseman' FROM tbldepartments WHERE dept_name = 'Warehouse Department';

-- Retail Operations Department (alphabetical)
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Assistant Store Manager' FROM tbldepartments WHERE dept_name = 'Retail Operations Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Bagger' FROM tbldepartments WHERE dept_name = 'Retail Operations Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Cashier' FROM tbldepartments WHERE dept_name = 'Retail Operations Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Product Specialist' FROM tbldepartments WHERE dept_name = 'Retail Operations Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Retail Supervisor' FROM tbldepartments WHERE dept_name = 'Retail Operations Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Store Manager' FROM tbldepartments WHERE dept_name = 'Retail Operations Department';

-- IT Department (alphabetical)
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Cybersecurity Specialist' FROM tbldepartments WHERE dept_name = 'IT Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Database Administrator' FROM tbldepartments WHERE dept_name = 'IT Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'System Administrator' FROM tbldepartments WHERE dept_name = 'IT Department';
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'Web Developer' FROM tbldepartments WHERE dept_name = 'IT Department';

-- Human Resources Department
INSERT IGNORE INTO tbldepartment_positions (dept_id, position_name)
SELECT dept_id, 'HR DIRECTOR' FROM tbldepartments WHERE dept_name = 'Human Resources Department';

-- Table: tblemployees
CREATE TABLE IF NOT EXISTS tblemployees (
    employee_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    middle_name VARCHAR(50) NULL,
    last_name VARCHAR(50) NOT NULL,
    date_of_birth DATE NULL,
    gender ENUM('male','female') NULL,
    email VARCHAR(100) UNIQUE,
    phone VARCHAR(20),
    profile_image LONGTEXT NULL,
    address TEXT,
    department VARCHAR(50),
    position VARCHAR(50),
    basic_salary DECIMAL(10,2) NOT NULL,
    salary_rate_type ENUM('monthly','daily','hourly') DEFAULT 'monthly',
    date_hired DATE,
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblusers (for login and roles)
CREATE TABLE IF NOT EXISTS tblusers (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'employee', 'manager', 'hr') NOT NULL,
    employee_id INT DEFAULT NULL,
    avatar_url VARCHAR(255) DEFAULT NULL,
    reset_code VARCHAR(6) DEFAULT NULL,
    reset_code_expires DATETIME DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_users_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblattendance
CREATE TABLE IF NOT EXISTS tblattendance (
    attendance_id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    attendance_date DATE NOT NULL,
    time_in TIME,
    time_out TIME,
    status ENUM('present', 'absent', 'leave', 'late', 'undertime') DEFAULT 'present',
    remarks VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_att_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    UNIQUE KEY uniq_attendance_employee_date (employee_id, attendance_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblemployee_financial_details
CREATE TABLE IF NOT EXISTS tblemployee_financial_details (
    fin_id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    bank_account VARCHAR(100) NULL,
    tax_id VARCHAR(50) NULL,
    sss_number VARCHAR(50) NULL,
    philhealth_number VARCHAR(50) NULL,
    pagibig_number VARCHAR(50) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_employee_fin (employee_id),
    CONSTRAINT fk_fin_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblpayroll_period
CREATE TABLE IF NOT EXISTS tblpayroll_period (
    period_id INT AUTO_INCREMENT PRIMARY KEY,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    status ENUM('open','closed') DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_payroll_period (period_start, period_end)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed a sample payroll period (idempotent)
INSERT IGNORE INTO tblpayroll_period (period_start, period_end, status) VALUES
('2025-08-01', '2025-08-15', 'open');

-- Table: tblemployee_workday_summary
CREATE TABLE IF NOT EXISTS tblemployee_workday_summary (
    summary_id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    period_id INT NOT NULL,
    total_workdays INT NOT NULL DEFAULT 0,
    days_present INT NOT NULL DEFAULT 0,
    days_absent INT NOT NULL DEFAULT 0,
    days_leave INT NOT NULL DEFAULT 0,
    days_late INT NOT NULL DEFAULT 0,
    total_hours_worked DECIMAL(7,2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_emp_period_summary (employee_id, period_id),
    INDEX idx_ews_period (period_id),
    CONSTRAINT fk_ews_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_ews_period FOREIGN KEY (period_id) REFERENCES tblpayroll_period(period_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblpayroll
CREATE TABLE IF NOT EXISTS tblpayroll (
    payroll_id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    payroll_period_start DATE NOT NULL,
    payroll_period_end DATE NOT NULL,
    basic_salary DECIMAL(10,2) NOT NULL,
    total_overtime_hours DECIMAL(5,2) DEFAULT 0,
    overtime_pay DECIMAL(10,2) DEFAULT 0,
    deductions DECIMAL(10,2) DEFAULT 0,
    net_pay DECIMAL(10,2) NOT NULL,
    status ENUM('processed','paid') DEFAULT 'processed',
    paid_at DATETIME NULL,
    paid_by INT NULL,
    slip_downloaded_at DATETIME NULL,
    slip_download_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_payroll_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_payroll_paid_by FOREIGN KEY (paid_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    INDEX idx_payroll_status (status),
    INDEX idx_payroll_period (employee_id, payroll_period_start, payroll_period_end)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblpayroll_slip_downloads
CREATE TABLE IF NOT EXISTS tblpayroll_slip_downloads (
    download_id INT AUTO_INCREMENT PRIMARY KEY,
    payroll_id INT NOT NULL,
    user_id INT NULL,
    downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    CONSTRAINT fk_psd_payroll FOREIGN KEY (payroll_id) REFERENCES tblpayroll(payroll_id) ON DELETE CASCADE,
    CONSTRAINT fk_psd_user FOREIGN KEY (user_id) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    INDEX idx_psd_payroll (payroll_id),
    INDEX idx_psd_downloaded_at (downloaded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblpayslip_history
CREATE TABLE IF NOT EXISTS tblpayslip_history (
    history_id INT AUTO_INCREMENT PRIMARY KEY,
    payroll_id INT NOT NULL,
    employee_id INT NOT NULL,
    payroll_period_start DATE NOT NULL,
    payroll_period_end DATE NOT NULL,
    basic_salary DECIMAL(10,2) NOT NULL,
        total_overtime_hours DECIMAL(5,2) DEFAULT 0,
    overtime_pay DECIMAL(10,2) DEFAULT 0,
    total_deductions DECIMAL(10,2) DEFAULT 0,
    net_pay DECIMAL(10,2) NOT NULL,
    snapshot_details LONGTEXT NULL,
    file_path VARCHAR(255) NULL,
    generated_by INT NULL,
    generated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_payslip_per_payroll_employee (payroll_id, employee_id),
    INDEX idx_ph_payroll (payroll_id),
    INDEX idx_ph_employee (employee_id),
    INDEX idx_ph_generated_at (generated_at),
    CONSTRAINT fk_ph_payroll FOREIGN KEY (payroll_id) REFERENCES tblpayroll(payroll_id) ON DELETE CASCADE,
    CONSTRAINT fk_ph_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_ph_generated_by FOREIGN KEY (generated_by) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblpayroll_archive
CREATE TABLE IF NOT EXISTS tblpayroll_archive (
    archive_id INT AUTO_INCREMENT PRIMARY KEY,
    payroll_id INT NOT NULL,
    employee_id INT NOT NULL,
    payroll_period_start DATE NOT NULL,
    payroll_period_end DATE NOT NULL,
    basic_salary DECIMAL(10,2) NOT NULL,
    total_overtime_hours DECIMAL(5,2) DEFAULT 0.00,
    overtime_pay DECIMAL(10,2) DEFAULT 0.00,
    total_deductions DECIMAL(10,2) DEFAULT 0.00,
    net_pay DECIMAL(10,2) NOT NULL,
    status ENUM('processed','paid') DEFAULT 'processed',
    archived_reason VARCHAR(255) NULL,
    archived_by INT NULL,
    archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_parch_payroll FOREIGN KEY (payroll_id) REFERENCES tblpayroll(payroll_id) ON DELETE CASCADE,
    CONSTRAINT fk_parch_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_parch_archived_by FOREIGN KEY (archived_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    INDEX idx_parch_payroll (payroll_id),
    INDEX idx_parch_employee (employee_id),
    INDEX idx_parch_archived_at (archived_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblleaves
CREATE TABLE IF NOT EXISTS tblleaves (
    leave_id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    reason VARCHAR(255),
    leave_type ENUM('vacation','sick leave','birthday leave','deductible against pay','maternity','paternity') NOT NULL DEFAULT 'vacation',
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    approved_by INT NULL,
    approved_at DATETIME NULL,
    rejected_by INT NULL,
    rejected_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_leaves_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_leaves_approved_by FOREIGN KEY (approved_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_leaves_rejected_by FOREIGN KEY (rejected_by) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblleave_archive
CREATE TABLE IF NOT EXISTS tblleave_archive (
    archive_id INT AUTO_INCREMENT PRIMARY KEY,
    leave_id INT NOT NULL,
    employee_id INT NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    reason VARCHAR(255) NULL,
    leave_type ENUM('vacation','sick leave','birthday leave','deductible against pay','maternity','paternity') NOT NULL DEFAULT 'vacation',
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    approved_by INT NULL,
    approved_at DATETIME NULL,
    rejected_by INT NULL,
    rejected_at DATETIME NULL,
    created_at TIMESTAMP NULL,
    archived_reason VARCHAR(255) NULL,
    archived_by INT NULL,
    archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_larch_leave FOREIGN KEY (leave_id) REFERENCES tblleaves(leave_id) ON DELETE CASCADE,
    CONSTRAINT fk_larch_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_larch_approved_by FOREIGN KEY (approved_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_larch_rejected_by FOREIGN KEY (rejected_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_larch_archived_by FOREIGN KEY (archived_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    INDEX idx_larch_leave (leave_id),
    INDEX idx_larch_employee (employee_id),
    INDEX idx_larch_status (status),
    INDEX idx_larch_archived_at (archived_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- New Leave Types table for managing selectable leave types
CREATE TABLE IF NOT EXISTS tblleave_types (
    type_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    sort_order INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_leave_types_name (name),
    INDEX idx_leave_types_active (is_active),
    INDEX idx_leave_types_sort (sort_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed leave types (idempotent)
INSERT IGNORE INTO tblleave_types (name, description, is_active, sort_order) VALUES
('vacation', 'Paid time off for rest or personal matters', 1, 1),
('sick leave', 'Leave due to illness', 1, 2),
('birthday leave', 'Leave for birthday', 1, 3),
('deductible against pay', 'Unpaid leave, deducted from pay', 1, 4),
('maternity', 'Maternity leave', 1, 5),
('paternity', 'Paternity leave', 1, 6);

-- Table: tblleave_cancellations
CREATE TABLE IF NOT EXISTS tblleave_cancellations (
    cancel_id INT AUTO_INCREMENT PRIMARY KEY,
    leave_id INT NOT NULL,
    employee_id INT NOT NULL,
    cancelled_by_user_id INT NULL,
    reason VARCHAR(255) NULL,
    cancelled_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_lc_leave FOREIGN KEY (leave_id) REFERENCES tblleaves(leave_id) ON DELETE CASCADE,
    CONSTRAINT fk_lc_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_lc_cancelled_by FOREIGN KEY (cancelled_by_user_id) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblnotifications
CREATE TABLE IF NOT EXISTS tblnotifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    message VARCHAR(255) NOT NULL,
    type VARCHAR(30) NULL,
    actor_user_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at DATETIME NULL,
    CONSTRAINT fk_notifications_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_notifications_actor FOREIGN KEY (actor_user_id) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tbldeductions
CREATE TABLE IF NOT EXISTS tbldeductions (
    deduct_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    amount DECIMAL(12,2) DEFAULT 0,
    amount_type ENUM('fixed','percent') DEFAULT 'fixed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_deductions_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed deductions (idempotent)
INSERT IGNORE INTO tbldeductions (name, description, amount, amount_type) VALUES
('SSS', 'Social Security System', 5.00, 'percent'),
('PhilHealth', 'PhilHealth contribution', 300.00, 'fixed'),
('Pag-IBIG', 'Pag-IBIG (HDMF) contribution', 100.00, 'fixed'),
('Withholding Tax', 'Income tax withholding', 0.00, 'fixed'),
('Provident Fund', 'Provident Fund contribution', 10.00, 'percent');

-- Table: tblemployee_deductions
CREATE TABLE IF NOT EXISTS tblemployee_deductions (
    emp_deduct_id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    deduct_id INT NOT NULL,
    value DECIMAL(12,2) DEFAULT NULL,
    CONSTRAINT fk_empded_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_empded_deduct FOREIGN KEY (deduct_id) REFERENCES tbldeductions(deduct_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;




-- Table: tblsystem_settings
CREATE TABLE IF NOT EXISTS tblsystem_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed settings (idempotent, update if exists)
INSERT INTO tblsystem_settings (setting_key, setting_value) VALUES
('company_name', 'My Company'),
('overtime_multiplier', '1.25'),
('undertime_deduction_per_hour', '100.00'),
('payroll_currency', 'PHP'),
('default_vacation_days', '5'),
('default_sick_days', '5'),
('ui_theme', 'blue'),
('ui_theme_primary_600', '#2563eb'),
('ui_theme_primary_700', '#1d4ed8'),
('account_lock_enabled', '0'),
('account_lock_max_attempts', '5'),
('account_lock_window_minutes', '15'),
('account_lockout_minutes', '30'),
('account_allow_admin_unblock', '1'),
('company_address', '123 Main St, City, Country'),
('system_profile', 'production'),
('work_week', '["mon","tue","wed","thu","fri"]'),
('clock_in_method', 'qr'),
('standard_work_start_time', '08:00'),
('standard_work_end_time', '17:00'),
('allow_break_scans', '1'),
('overtime_tracking_enabled', '1'),
('work_hours_per_day', '12'),
('grace_period_minutes', '0'),
('developed_by', ''),
('notify_type', 'general'),
('notify_recipients', ''),
('notify_recipient', ''),
('notify_message', ''),
('notify_delivery_option', 'in_app'),
('pay_period', 'semi_monthly'),
('salary_basis', 'monthly'),
('sss_enabled', '1'),
('philhealth_enabled', '1'),
('pagibig_enabled', '1'),
('tax_enabled', '1'),
('late_deduction_enabled', '1'),
('late_deduction_per_minute', '0'),
('absent_deduction_enabled', '1'),
('absent_deduction_per_day', '0'),
('loans_enabled', '1'),
('ot_regular_multiplier', '1.25'),
('ot_rest_day_multiplier', '1.30'),
('ot_special_holiday_multiplier', '1.50'),
('ot_regular_holiday_multiplier', '2.00'),
('undertime_grace_minutes', '0')
ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);

-- Additional System Configuration defaults

-- Table: tblaudit_logs
CREATE TABLE IF NOT EXISTS tblaudit_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblovertime_requests
CREATE TABLE IF NOT EXISTS tblovertime_requests (
    ot_id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    work_date DATE NOT NULL,
    start_time TIME NULL,
    end_time TIME NULL,
    hours DECIMAL(5,2) DEFAULT NULL,
    reason VARCHAR(255) NULL,
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    approved_by INT NULL,
    approved_at DATETIME NULL,
    rejected_by INT NULL,
    rejected_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ot_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_ot_approved_by FOREIGN KEY (approved_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_ot_rejected_by FOREIGN KEY (rejected_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    INDEX idx_ot_employee_date (employee_id, work_date),
    INDEX idx_ot_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblundertime_requests
CREATE TABLE IF NOT EXISTS tblundertime_requests (
    ut_id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id INT NOT NULL,
    work_date DATE NOT NULL,
    hours DECIMAL(5,2) NOT NULL,
    reason VARCHAR(255) NULL,
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    approved_by INT NULL,
    approved_at DATETIME NULL,
    rejected_by INT NULL,
    rejected_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ut_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_ut_approved_by FOREIGN KEY (approved_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_ut_rejected_by FOREIGN KEY (rejected_by) REFERENCES tblusers(user_id) ON DELETE SET NULL,
    INDEX idx_ut_employee_date (employee_id, work_date),
    INDEX idx_ut_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Report tables
CREATE TABLE IF NOT EXISTS tblPayrollReports (
    Report_ID INT AUTO_INCREMENT PRIMARY KEY,
    Payroll_ID INT NOT NULL,
    Employee_ID INT NOT NULL,
    Period_Start DATE NOT NULL,
    Period_End DATE NOT NULL,
    Basic_Salary DECIMAL(10,2) NOT NULL,
        Total_Deductions DECIMAL(10,2) DEFAULT 0.00,
    Net_Pay DECIMAL(10,2) NOT NULL,
    Generated_By INT NULL,
    Generated_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_pr_payroll FOREIGN KEY (Payroll_ID) REFERENCES tblpayroll(payroll_id) ON DELETE CASCADE,
    CONSTRAINT fk_pr_employee FOREIGN KEY (Employee_ID) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_pr_generated_by FOREIGN KEY (Generated_By) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tblAttendanceReports (
    Report_ID INT AUTO_INCREMENT PRIMARY KEY,
    Attendance_ID INT NOT NULL,
    Employee_ID INT NOT NULL,
    Period_Start DATE NOT NULL,
    Period_End DATE NOT NULL,
    Days_Present INT DEFAULT 0,
    Days_Absent INT DEFAULT 0,
    Days_Leave INT DEFAULT 0,
    Days_Late INT DEFAULT 0,
    Total_Hours_Worked DECIMAL(7,2) DEFAULT 0.00,
    Generated_By INT NULL,
    Generated_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ar_attendance FOREIGN KEY (Attendance_ID) REFERENCES tblattendance(attendance_id) ON DELETE CASCADE,
    CONSTRAINT fk_ar_employee FOREIGN KEY (Employee_ID) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_ar_generated_by FOREIGN KEY (Generated_By) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tblEmployeeReports (
    Report_ID INT AUTO_INCREMENT PRIMARY KEY,
    Employee_ID INT NOT NULL,
    Department_ID INT NULL,
    Position VARCHAR(100) NULL,
    Basic_Salary DECIMAL(10,2) NOT NULL,
    Status ENUM('active','inactive') DEFAULT 'active',
    Date_Hired DATE NULL,
    Generated_By INT NULL,
    Generated_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_er_employee FOREIGN KEY (Employee_ID) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_er_department FOREIGN KEY (Department_ID) REFERENCES tbldepartments(dept_id) ON DELETE SET NULL,
    CONSTRAINT fk_er_generated_by FOREIGN KEY (Generated_By) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tblDepartmentReports (
    Report_ID INT AUTO_INCREMENT PRIMARY KEY,
    Department_ID INT NOT NULL,
    Total_Employees INT DEFAULT 0,
    Total_Salary DECIMAL(12,2) DEFAULT 0.00,
    Generated_By INT NULL,
    Generated_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_dr_department FOREIGN KEY (Department_ID) REFERENCES tbldepartments(dept_id) ON DELETE CASCADE,
    CONSTRAINT fk_dr_generated_by FOREIGN KEY (Generated_By) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tblDeductionReports (
    Report_ID INT AUTO_INCREMENT PRIMARY KEY,
    Deduction_ID INT NOT NULL,
    Employee_ID INT NOT NULL,
    Payroll_ID INT NULL,
    Deduction_Amount DECIMAL(10,2) DEFAULT 0.00,
    Period_Start DATE NULL,
    Period_End DATE NULL,
    Generated_By INT NULL,
    Generated_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_dr_deduction FOREIGN KEY (Deduction_ID) REFERENCES tbldeductions(deduct_id) ON DELETE CASCADE,
    CONSTRAINT fk_dr_employee FOREIGN KEY (Employee_ID) REFERENCES tblemployees(employee_id) ON DELETE CASCADE,
    CONSTRAINT fk_dr_payroll FOREIGN KEY (Payroll_ID) REFERENCES tblpayroll(payroll_id) ON DELETE SET NULL,
    CONSTRAINT fk_dr_generated_by2 FOREIGN KEY (Generated_By) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblholidays
CREATE TABLE IF NOT EXISTS tblholidays (
    id INT AUTO_INCREMENT PRIMARY KEY,
    holiday_date DATE NOT NULL,
    holiday_name VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblattendance_daily_summary
CREATE TABLE IF NOT EXISTS tblattendance_daily_summary (
    summary_id INT(11) NOT NULL AUTO_INCREMENT,
    summary_date DATE NOT NULL,
    total_present INT(11) DEFAULT 0,
    total_absent INT(11) DEFAULT 0,
    total_late INT(11) DEFAULT 0,
    total_leave INT(11) DEFAULT 0,
    total_undertime INT(11) DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (summary_id),
    UNIQUE KEY uniq_summary_date (summary_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblattendance_employee_daily
CREATE TABLE IF NOT EXISTS tblattendance_employee_daily (
    id INT(11) NOT NULL AUTO_INCREMENT,
    employee_id INT(11) NOT NULL,
    attendance_date DATE NOT NULL,
    status ENUM('present','absent','leave','late','undertime') NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_emp_date (employee_id, attendance_date),
    CONSTRAINT fk_emp_daily_employee FOREIGN KEY (employee_id)
        REFERENCES tblemployees (employee_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblpayroll_by_batch
CREATE TABLE IF NOT EXISTS tblpayroll_by_batch (
    batch_id INT AUTO_INCREMENT PRIMARY KEY,
    batch_name VARCHAR(100) NOT NULL,
    payroll_period_start DATE NOT NULL,
    payroll_period_end DATE NOT NULL,
    department VARCHAR(100) DEFAULT NULL,
    total_employees INT DEFAULT 0,
    total_amount DECIMAL(12,2) DEFAULT 0.00,
    status ENUM('pending','processing','completed','failed') DEFAULT 'pending',
    notes TEXT DEFAULT NULL,
    generated_by INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_pbb_generated_by FOREIGN KEY (generated_by) REFERENCES tblusers(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: tblpayroll_batch_employees
CREATE TABLE IF NOT EXISTS tblpayroll_batch_employees (
    batch_emp_id INT AUTO_INCREMENT PRIMARY KEY,
    batch_id INT NOT NULL,
    employee_id INT NOT NULL,
    basic_salary DECIMAL(10,2) NOT NULL,
    overtime_pay DECIMAL(10,2) DEFAULT 0.00,
    deductions DECIMAL(10,2) DEFAULT 0.00,
    net_pay DECIMAL(10,2) NOT NULL,
    status ENUM('pending','processed','paid') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_pbe_batch FOREIGN KEY (batch_id) REFERENCES tblpayroll_by_batch(batch_id) ON DELETE CASCADE,
    CONSTRAINT fk_pbe_employee FOREIGN KEY (employee_id) REFERENCES tblemployees(employee_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

