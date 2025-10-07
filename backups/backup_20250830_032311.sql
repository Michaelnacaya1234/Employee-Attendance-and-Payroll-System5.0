-- Database Backup
-- Generated: 2025-08-30T03:23:11+02:00
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS=0;
START TRANSACTION;
USE `dbattendance`;

-- 
-- Structure for table `tblallowances`
-- 
DROP TABLE IF EXISTS `tblallowances`;
CREATE TABLE `tblallowances` (
  `allowance_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `amount` decimal(12,2) DEFAULT 0.00,
  `amount_type` enum('fixed','percent') DEFAULT 'fixed',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`allowance_id`),
  UNIQUE KEY `uniq_allowances_name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblallowances` (`allowance_id`,`name`,`description`,`amount`,`amount_type`,`created_at`) VALUES ('1','Transportation','Transport allowance','1000.00','fixed','2025-08-20 17:35:06'),
('2','Meal','Meal allowance','500.00','fixed','2025-08-20 17:35:06');

-- 
-- Structure for table `tblattendance`
-- 
DROP TABLE IF EXISTS `tblattendance`;
CREATE TABLE `tblattendance` (
  `attendance_id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `attendance_date` date NOT NULL,
  `time_in` time DEFAULT NULL,
  `time_out` time DEFAULT NULL,
  `status` enum('present','absent','leave','late','undertime') DEFAULT 'present',
  `remarks` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`attendance_id`),
  UNIQUE KEY `uniq_attendance_employee_date` (`employee_id`,`attendance_date`),
  CONSTRAINT `fk_att_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 
-- Structure for table `tblattendancereports`
-- 
DROP TABLE IF EXISTS `tblattendancereports`;
CREATE TABLE `tblattendancereports` (
  `Report_ID` int(11) NOT NULL AUTO_INCREMENT,
  `Attendance_ID` int(11) NOT NULL,
  `Employee_ID` int(11) NOT NULL,
  `Period_Start` date NOT NULL,
  `Period_End` date NOT NULL,
  `Days_Present` int(11) DEFAULT 0,
  `Days_Absent` int(11) DEFAULT 0,
  `Days_Leave` int(11) DEFAULT 0,
  `Days_Late` int(11) DEFAULT 0,
  `Total_Hours_Worked` decimal(7,2) DEFAULT 0.00,
  `Generated_By` int(11) DEFAULT NULL,
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`Report_ID`),
  KEY `fk_ar_attendance` (`Attendance_ID`),
  KEY `fk_ar_employee` (`Employee_ID`),
  KEY `fk_ar_generated_by` (`Generated_By`),
  CONSTRAINT `fk_ar_attendance` FOREIGN KEY (`Attendance_ID`) REFERENCES `tblattendance` (`attendance_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ar_employee` FOREIGN KEY (`Employee_ID`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ar_generated_by` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 
-- Structure for table `tblaudit_logs`
-- 
DROP TABLE IF EXISTS `tblaudit_logs`;
CREATE TABLE `tblaudit_logs` (
  `log_id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(255) NOT NULL,
  `details` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`log_id`),
  KEY `fk_audit_user` (`user_id`),
  CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=117 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblaudit_logs` (`log_id`,`user_id`,`action`,`details`,`ip_address`,`created_at`) VALUES ('1','1','login','User admin logged in successfully','::1','2025-08-20 17:42:11'),
('2','1','logout','User admin logged out','::1','2025-08-20 18:49:37'),
('3','9','login','User mjay@gmail.com logged in successfully','::1','2025-08-20 18:49:46'),
('4','9','logout','User mjay@gmail.com logged out','::1','2025-08-20 18:50:05'),
('5','1','login','User admin logged in successfully','::1','2025-08-20 18:50:09'),
('6','1','logout','User admin logged out','::1','2025-08-20 18:51:04'),
('7','1','login','User admin logged in successfully','::1','2025-08-20 18:51:09'),
('8','1','login','User admin logged in successfully','::1','2025-08-20 19:00:57'),
('9','1','logout','User admin logged out','::1','2025-08-20 19:29:39'),
('10','14','login','User maria@gmail.com logged in successfully','::1','2025-08-20 19:30:23'),
('11','14','logout','User maria@gmail.com logged out','::1','2025-08-20 19:36:40'),
('12','3','login','User michael@gmail.com logged in successfully','::1','2025-08-20 19:36:49'),
('13','3','logout','User michael@gmail.com logged out','::1','2025-08-20 19:36:52'),
('14','14','login','User maria@gmail.com logged in successfully','::1','2025-08-20 19:37:10'),
('15','14','login','User maria@gmail.com logged in successfully','::1','2025-08-20 19:39:41'),
('16','14','logout','User maria@gmail.com logged out','::1','2025-08-20 19:45:18'),
('17','1','login','User admin logged in successfully','::1','2025-08-20 19:45:24'),
('18','1','login','User admin logged in successfully','::1','2025-08-30 07:15:07'),
('19','1','update_security_settings','Updated security settings: [\"password_min_length\",\"password_require_uppercase\",\"password_require_number\",\"password_require_special\",\"password_expiry_days\",\"two_factor_enabled\",\"session_timeout_minutes\",\"remember_me_enabled\",\"account_lockout_threshold\",\"account_lockout_duration_minutes\",\"account_lockout_escalation_enabled\",\"account_lockout_first_minutes\",\"account_lockout_second_minutes\",\"account_lockout_third_minutes\",\"account_lockout_escalation_attempts_enabled\",\"account_lockout_first_attempts\",\"account_lockout_second_attempts\",\"account_lockout_third_attempts\"]','::1','2025-08-30 07:16:00'),
('20','1','logout','User admin logged out','::1','2025-08-30 07:16:13'),
('21','1','login','User admin logged in successfully','::1','2025-08-30 07:16:19'),
('22','1','logout','User admin logged out','::1','2025-08-30 07:16:48'),
('23','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:17:15'),
('24','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:17:16'),
('25','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:17:17'),
('26','9','login_lockout','{\"username\":\"mjay@gmail.com\",\"lockout_until\":\"2025-08-30 01:18:17\",\"threshold\":0,\"duration_minutes\":1,\"ip\":\"::1\",\"escalation\":{\"first\":1,\"second\":2,\"third\":3},\"lockout_level\":\"first\"}','::1','2025-08-30 07:17:17'),
('27',NULL,'login_failed','Failed login for unknown user admin123','::1','2025-08-30 07:17:53'),
('28','1','login','User admin logged in successfully','::1','2025-08-30 07:17:56'),
('29','1','update_security_settings','Updated security settings: [\"password_min_length\",\"password_require_uppercase\",\"password_require_number\",\"password_require_special\",\"password_expiry_days\",\"two_factor_enabled\",\"session_timeout_minutes\",\"remember_me_enabled\",\"account_lockout_threshold\",\"account_lockout_duration_minutes\",\"account_lockout_escalation_enabled\",\"account_lockout_first_minutes\",\"account_lockout_second_minutes\",\"account_lockout_third_minutes\",\"account_lockout_escalation_attempts_enabled\",\"account_lockout_first_attempts\",\"account_lockout_second_attempts\",\"account_lockout_third_attempts\"]','::1','2025-08-30 07:18:15'),
('30','1','update_security_settings','Updated security settings: [\"password_min_length\",\"password_require_uppercase\",\"password_require_number\",\"password_require_special\",\"password_expiry_days\",\"two_factor_enabled\",\"session_timeout_minutes\",\"remember_me_enabled\",\"account_lockout_threshold\",\"account_lockout_duration_minutes\",\"account_lockout_escalation_enabled\",\"account_lockout_first_minutes\",\"account_lockout_second_minutes\",\"account_lockout_third_minutes\",\"account_lockout_escalation_attempts_enabled\",\"account_lockout_first_attempts\",\"account_lockout_second_attempts\",\"account_lockout_third_attempts\"]','::1','2025-08-30 07:20:42'),
('31','1','logout','User admin logged out','::1','2025-08-30 07:20:48'),
('32','9','login','User mjay@gmail.com logged in successfully','::1','2025-08-30 07:20:56'),
('33','9','logout','User mjay@gmail.com logged out','::1','2025-08-30 07:21:58'),
('34','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:22:17'),
('35','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:22:18'),
('36','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:22:18'),
('37','9','login_lockout','{\"username\":\"mjay@gmail.com\",\"lockout_until\":\"2025-08-30 01:23:18\",\"threshold\":0,\"duration_minutes\":1,\"ip\":\"::1\",\"escalation\":{\"first\":1,\"second\":2,\"third\":3},\"lockout_level\":\"first\"}','::1','2025-08-30 07:22:18'),
('38','1','login','User admin logged in successfully','::1','2025-08-30 07:22:32'),
('39','1','logout','User admin logged out','::1','2025-08-30 07:23:33'),
('40','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:23:48'),
('41','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:23:48'),
('42','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:23:48'),
('43','9','login_lockout','{\"username\":\"mjay@gmail.com\",\"lockout_until\":\"2025-08-30 01:25:48\",\"threshold\":0,\"duration_minutes\":2,\"ip\":\"::1\",\"escalation\":{\"first\":1,\"second\":2,\"third\":3},\"lockout_level\":\"second\"}','::1','2025-08-30 07:23:48'),
('44','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:25:48'),
('45','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:25:49'),
('46','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:25:50'),
('47','9','login_lockout','{\"username\":\"mjay@gmail.com\",\"lockout_until\":\"2025-08-30 01:28:50\",\"threshold\":0,\"duration_minutes\":3,\"ip\":\"::1\",\"escalation\":{\"first\":1,\"second\":2,\"third\":3},\"lockout_level\":\"third+\"}','::1','2025-08-30 07:25:50'),
('48','1','login','User admin logged in successfully','::1','2025-08-30 07:26:04'),
('49','1','logout','User admin logged out','::1','2025-08-30 07:27:06'),
('50','1','login','User admin logged in successfully','::1','2025-08-30 07:27:27'),
('51','1','logout','User admin logged out','::1','2025-08-30 07:27:55'),
('52','9','login','User mjay@gmail.com logged in successfully','::1','2025-08-30 07:28:51'),
('53','9','logout','User mjay@gmail.com logged out','::1','2025-08-30 07:28:56'),
('54','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:29:04'),
('55','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:29:05'),
('56','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:29:05'),
('57','9','login_lockout','{\"username\":\"mjay@gmail.com\",\"lockout_until\":\"2025-08-30 01:30:05\",\"threshold\":0,\"duration_minutes\":1,\"ip\":\"::1\",\"escalation\":{\"first\":1,\"second\":2,\"third\":3},\"lockout_level\":\"first\"}','::1','2025-08-30 07:29:05'),
('58','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:30:40'),
('59','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:30:41'),
('60','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:30:41'),
('61','9','login_lockout','{\"username\":\"mjay@gmail.com\",\"lockout_until\":\"2025-08-30 01:32:41\",\"threshold\":0,\"duration_minutes\":2,\"ip\":\"::1\",\"escalation\":{\"first\":1,\"second\":2,\"third\":3},\"lockout_level\":\"second\"}','::1','2025-08-30 07:30:41'),
('62','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:32:41'),
('63','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:32:44'),
('64','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:32:45'),
('65','9','login_lockout','{\"username\":\"mjay@gmail.com\",\"lockout_until\":\"2025-08-30 01:35:45\",\"threshold\":0,\"duration_minutes\":3,\"ip\":\"::1\",\"escalation\":{\"first\":1,\"second\":2,\"third\":3},\"lockout_level\":\"third+\"}','::1','2025-08-30 07:32:45'),
('66','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:35:52'),
('67','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:35:54'),
('68','9','login_failed','Failed login for user mjay@gmail.com','::1','2025-08-30 07:35:54'),
('69','9','account_blocked','{\"username\":\"mjay@gmail.com\",\"reason\":\"Exceeded maximum lockouts (4th lockout)\",\"failed_attempts_count\":3,\"ip\":\"::1\"}','::1','2025-08-30 07:35:54'),
('70','1','login','User admin logged in successfully','::1','2025-08-30 07:36:23'),
('71','1','logout','User admin logged out','::1','2025-08-30 07:37:31'),
('72','11','login','User dave@gmail.com logged in successfully','::1','2025-08-30 08:02:51'),
('73','11','logout','User dave@gmail.com logged out','::1','2025-08-30 08:02:56'),
('74','1','login','User admin logged in successfully','::1','2025-08-30 08:03:30'),
('75','1','logout','User admin logged out','::1','2025-08-30 08:04:50'),
('76','1','login','User admin logged in successfully','::1','2025-08-30 08:05:04'),
('77','1','logout','User admin logged out','::1','2025-08-30 08:06:53'),
('78','1','login','User admin logged in successfully','::1','2025-08-30 08:09:36'),
('79','1','logout','User admin logged out','::1','2025-08-30 08:10:43'),
('80','1','login','User admin logged in successfully','::1','2025-08-30 08:13:01'),
('81','1','logout','User admin logged out','::1','2025-08-30 08:14:02'),
('82','1','login','User admin logged in successfully','::1','2025-08-30 08:14:36'),
('83','9','account_unblocked','Account unblocked by admin','::1','2025-08-30 08:14:51'),
('84','1','update_security_settings','Updated security settings: [\"password_min_length\",\"password_require_uppercase\",\"password_require_number\",\"password_require_special\",\"password_expiry_days\",\"two_factor_enabled\",\"session_timeout_minutes\",\"remember_me_enabled\",\"account_lockout_threshold\",\"account_lockout_duration_minutes\",\"account_lockout_escalation_enabled\",\"account_lockout_first_minutes\",\"account_lockout_second_minutes\",\"account_lockout_third_minutes\",\"account_lockout_escalation_attempts_enabled\",\"account_lockout_first_attempts\",\"account_lockout_second_attempts\",\"account_lockout_third_attempts\"]','::1','2025-08-30 08:14:57'),
('85','1','update_security_settings','Updated security settings: [\"password_min_length\",\"password_require_uppercase\",\"password_require_number\",\"password_require_special\",\"password_expiry_days\",\"two_factor_enabled\",\"session_timeout_minutes\",\"remember_me_enabled\",\"account_lockout_threshold\",\"account_lockout_duration_minutes\",\"account_lockout_escalation_enabled\",\"account_lockout_first_minutes\",\"account_lockout_second_minutes\",\"account_lockout_third_minutes\",\"account_lockout_escalation_attempts_enabled\",\"account_lockout_first_attempts\",\"account_lockout_second_attempts\",\"account_lockout_third_attempts\"]','::1','2025-08-30 08:14:59'),
('86','1','logout','User admin logged out','::1','2025-08-30 08:15:06'),
('87','9','login','User mjay@gmail.com logged in successfully','::1','2025-08-30 08:15:11'),
('88','9','logout','User mjay@gmail.com logged out','::1','2025-08-30 08:15:24'),
('89','1','login','User admin logged in successfully','::1','2025-08-30 08:15:29'),
('90','1','logout','User admin logged out','::1','2025-08-30 08:17:43'),
('91','1','login','User admin logged in successfully','::1','2025-08-30 08:22:20'),
('92','1','logout','User admin logged out','::1','2025-08-30 08:23:56'),
('93','1','login','User admin logged in successfully','::1','2025-08-30 08:24:19'),
('94','1','logout','User admin logged out','::1','2025-08-30 08:25:01'),
('95','9','login','User mjay@gmail.com logged in successfully','::1','2025-08-30 08:25:05'),
('96','9','logout','User mjay@gmail.com logged out','::1','2025-08-30 08:25:14'),
('97','14','login','User maria@gmail.com logged in successfully','::1','2025-08-30 08:25:23'),
('98','14','logout','User maria@gmail.com logged out','::1','2025-08-30 08:25:29'),
('99','1','login','User admin logged in successfully','::1','2025-08-30 08:25:34'),
('100','1','logout','User admin logged out','::1','2025-08-30 08:26:46'),
('101','14','login','User maria@gmail.com logged in successfully','::1','2025-08-30 08:28:17'),
('102','14','logout','User maria@gmail.com logged out','::1','2025-08-30 08:30:54'),
('103','14','login','User maria@gmail.com logged in successfully','::1','2025-08-30 08:32:20'),
('104','14','logout','User maria@gmail.com logged out','::1','2025-08-30 08:33:47'),
('105','1','login','User admin logged in successfully','::1','2025-08-30 08:36:33'),
('106','1','update_security_settings','Updated security settings: [\"password_min_length\",\"password_require_uppercase\",\"password_require_number\",\"password_require_special\",\"password_expiry_days\",\"two_factor_enabled\",\"session_timeout_minutes\",\"remember_me_enabled\",\"account_lockout_threshold\",\"account_lockout_duration_minutes\",\"account_lockout_escalation_enabled\",\"account_lockout_first_minutes\",\"account_lockout_second_minutes\",\"account_lockout_third_minutes\",\"account_lockout_escalation_attempts_enabled\",\"account_lockout_first_attempts\",\"account_lockout_second_attempts\",\"account_lockout_third_attempts\"]','::1','2025-08-30 08:37:01'),
('107','1','logout','User admin logged out','::1','2025-08-30 08:41:05'),
('108','14','login','User maria@gmail.com logged in successfully','::1','2025-08-30 08:44:54'),
('109','14','logout','User maria@gmail.com logged out','::1','2025-08-30 08:45:17'),
('110','1','login','User admin logged in successfully','::1','2025-08-30 08:45:27'),
('111','1','update_security_settings','Updated security settings: [\"password_min_length\",\"password_require_uppercase\",\"password_require_number\",\"password_require_special\",\"password_expiry_days\",\"two_factor_enabled\",\"session_timeout_minutes\",\"remember_me_enabled\",\"account_lockout_threshold\",\"account_lockout_duration_minutes\",\"account_lockout_escalation_enabled\",\"account_lockout_first_minutes\",\"account_lockout_second_minutes\",\"account_lockout_third_minutes\",\"account_lockout_escalation_attempts_enabled\",\"account_lockout_first_attempts\",\"account_lockout_second_attempts\",\"account_lockout_third_attempts\"]','::1','2025-08-30 08:45:58'),
('112','1','logout','User admin logged out','::1','2025-08-30 08:54:36'),
('113','1','login','User admin logged in successfully','::1','2025-08-30 08:57:49'),
('114','1','session_timeout','Session timed out due to inactivity','::1','2025-08-30 09:17:10'),
('115','1','login','User admin logged in successfully','::1','2025-08-30 09:17:55'),
('116','1','update_security_settings','Updated security settings: [\"password_min_length\",\"password_require_uppercase\",\"password_require_number\",\"password_require_special\",\"password_expiry_days\",\"two_factor_enabled\",\"session_timeout_minutes\",\"remember_me_enabled\",\"account_lockout_threshold\",\"account_lockout_duration_minutes\",\"account_lockout_escalation_enabled\",\"account_lockout_first_minutes\",\"account_lockout_second_minutes\",\"account_lockout_third_minutes\",\"account_lockout_escalation_attempts_enabled\",\"account_lockout_first_attempts\",\"account_lockout_second_attempts\",\"account_lockout_third_attempts\"]','::1','2025-08-30 09:20:58');

-- 
-- Structure for table `tbldeductionreports`
-- 
DROP TABLE IF EXISTS `tbldeductionreports`;
CREATE TABLE `tbldeductionreports` (
  `Report_ID` int(11) NOT NULL AUTO_INCREMENT,
  `Deduction_ID` int(11) NOT NULL,
  `Employee_ID` int(11) NOT NULL,
  `Payroll_ID` int(11) DEFAULT NULL,
  `Deduction_Amount` decimal(10,2) DEFAULT 0.00,
  `Period_Start` date DEFAULT NULL,
  `Period_End` date DEFAULT NULL,
  `Generated_By` int(11) DEFAULT NULL,
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`Report_ID`),
  KEY `fk_dr_deduction` (`Deduction_ID`),
  KEY `fk_dr_employee` (`Employee_ID`),
  KEY `fk_dr_payroll` (`Payroll_ID`),
  KEY `fk_dr_generated_by2` (`Generated_By`),
  CONSTRAINT `fk_dr_deduction` FOREIGN KEY (`Deduction_ID`) REFERENCES `tbldeductions` (`deduct_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_dr_employee` FOREIGN KEY (`Employee_ID`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_dr_generated_by2` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_dr_payroll` FOREIGN KEY (`Payroll_ID`) REFERENCES `tblpayroll` (`payroll_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 
-- Structure for table `tbldeductions`
-- 
DROP TABLE IF EXISTS `tbldeductions`;
CREATE TABLE `tbldeductions` (
  `deduct_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `amount` decimal(12,2) DEFAULT 0.00,
  `amount_type` enum('fixed','percent') DEFAULT 'fixed',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`deduct_id`),
  UNIQUE KEY `uniq_deductions_name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tbldeductions` (`deduct_id`,`name`,`description`,`amount`,`amount_type`,`created_at`) VALUES ('1','SSS','Social Security System','500.00','fixed','2025-08-20 17:35:06'),
('2','PhilHealth','PhilHealth contribution','300.00','fixed','2025-08-20 17:35:06');

-- 
-- Structure for table `tbldepartment_positions`
-- 
DROP TABLE IF EXISTS `tbldepartment_positions`;
CREATE TABLE `tbldepartment_positions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `dept_id` int(11) NOT NULL,
  `position_name` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_dept_position` (`dept_id`,`position_name`),
  CONSTRAINT `fk_dp_department` FOREIGN KEY (`dept_id`) REFERENCES `tbldepartments` (`dept_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tbldepartment_positions` (`id`,`dept_id`,`position_name`) VALUES ('5','1','Accountant'),
('6','1','Accounts Payable Clerk'),
('7','1','Accounts Receivable Clerk'),
('8','1','Cash Handling Specialist'),
('9','1','Payroll Specialist'),
('25','2','HR DIRECTOR'),
('21','3','Cybersecurity Specialist'),
('22','3','Database Administrator'),
('23','3','System Administrator'),
('24','3','Web Developer'),
('1','4','Content Writer'),
('2','4','Event Coordinator'),
('3','4','Marketing Manager'),
('4','4','Social Media Specialist'),
('15','5','Assistant Store Manager'),
('16','5','Bagger'),
('17','5','Cashier'),
('18','5','Product Specialist'),
('19','5','Retail Supervisor'),
('20','5','Store Manager'),
('10','6','Assistant Head'),
('11','6','Diser'),
('12','6','Head'),
('13','6','Merchandiser'),
('14','6','Warehouseman');

-- 
-- Structure for table `tbldepartmentreports`
-- 
DROP TABLE IF EXISTS `tbldepartmentreports`;
CREATE TABLE `tbldepartmentreports` (
  `Report_ID` int(11) NOT NULL AUTO_INCREMENT,
  `Department_ID` int(11) NOT NULL,
  `Total_Employees` int(11) DEFAULT 0,
  `Total_Salary` decimal(12,2) DEFAULT 0.00,
  `Generated_By` int(11) DEFAULT NULL,
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`Report_ID`),
  KEY `fk_dr_department` (`Department_ID`),
  KEY `fk_dr_generated_by` (`Generated_By`),
  CONSTRAINT `fk_dr_department` FOREIGN KEY (`Department_ID`) REFERENCES `tbldepartments` (`dept_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_dr_generated_by` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 
-- Structure for table `tbldepartments`
-- 
DROP TABLE IF EXISTS `tbldepartments`;
CREATE TABLE `tbldepartments` (
  `dept_id` int(11) NOT NULL AUTO_INCREMENT,
  `dept_name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`dept_id`),
  UNIQUE KEY `uniq_departments_name` (`dept_name`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tbldepartments` (`dept_id`,`dept_name`,`description`,`created_at`) VALUES ('1','Finance Department','Handles company finances','2025-08-20 17:35:05'),
('2','Human Resources Department','Oversees people operations','2025-08-20 17:35:05'),
('3','IT Department','Manages company IT systems','2025-08-20 17:35:05'),
('4','Marketing Department','Handles marketing and promotions','2025-08-20 17:35:05'),
('5','Retail Operations Department','Manages retail store operations','2025-08-20 17:35:05'),
('6','Warehouse Department','Oversees storage and inventory management','2025-08-20 17:35:05');

-- 
-- Structure for table `tblemployee_allowances`
-- 
DROP TABLE IF EXISTS `tblemployee_allowances`;
CREATE TABLE `tblemployee_allowances` (
  `emp_allow_id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `allowance_id` int(11) NOT NULL,
  `value` decimal(12,2) DEFAULT NULL,
  PRIMARY KEY (`emp_allow_id`),
  KEY `fk_empallow_employee` (`employee_id`),
  KEY `fk_empallow_allowance` (`allowance_id`),
  CONSTRAINT `fk_empallow_allowance` FOREIGN KEY (`allowance_id`) REFERENCES `tblallowances` (`allowance_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_empallow_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 
-- Structure for table `tblemployee_deductions`
-- 
DROP TABLE IF EXISTS `tblemployee_deductions`;
CREATE TABLE `tblemployee_deductions` (
  `emp_deduct_id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `deduct_id` int(11) NOT NULL,
  `value` decimal(12,2) DEFAULT NULL,
  PRIMARY KEY (`emp_deduct_id`),
  KEY `fk_empded_employee` (`employee_id`),
  KEY `fk_empded_deduct` (`deduct_id`),
  CONSTRAINT `fk_empded_deduct` FOREIGN KEY (`deduct_id`) REFERENCES `tbldeductions` (`deduct_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_empded_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 
-- Structure for table `tblemployee_financial_details`
-- 
DROP TABLE IF EXISTS `tblemployee_financial_details`;
CREATE TABLE `tblemployee_financial_details` (
  `fin_id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `bank_account` varchar(100) DEFAULT NULL,
  `tax_id` varchar(50) DEFAULT NULL,
  `sss_number` varchar(50) DEFAULT NULL,
  `philhealth_number` varchar(50) DEFAULT NULL,
  `pagibig_number` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`fin_id`),
  UNIQUE KEY `uniq_employee_fin` (`employee_id`),
  CONSTRAINT `fk_fin_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblemployee_financial_details` (`fin_id`,`employee_id`,`bank_account`,`tax_id`,`sss_number`,`philhealth_number`,`pagibig_number`,`created_at`) VALUES ('1','1','','','','','','2025-08-20 17:49:09'),
('2','2','','','','50000','','2025-08-20 17:49:52'),
('3','3','','','','555555','','2025-08-20 18:15:18'),
('4','4','','','','555555','','2025-08-20 18:16:29'),
('5','5','','','555555','','','2025-08-20 18:17:51'),
('7','6','','111111','','','','2025-08-20 18:46:51'),
('14','8','','5555555','','','','2025-08-20 19:03:06'),
('15','13','','5555555','','','','2025-08-20 19:19:48'),
('16','14','','5555555','','','','2025-08-20 19:21:05'),
('17','15','','','','5555','','2025-08-20 19:24:03'),
('18','16','','','5555555','','','2025-08-20 19:25:06'),
('19','18','','5555555','','','','2025-08-20 19:27:21');

-- 
-- Structure for table `tblemployee_workday_summary`
-- 
DROP TABLE IF EXISTS `tblemployee_workday_summary`;
CREATE TABLE `tblemployee_workday_summary` (
  `summary_id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `period_id` int(11) NOT NULL,
  `total_workdays` int(11) NOT NULL DEFAULT 0,
  `days_present` int(11) NOT NULL DEFAULT 0,
  `days_absent` int(11) NOT NULL DEFAULT 0,
  `days_leave` int(11) NOT NULL DEFAULT 0,
  `days_late` int(11) NOT NULL DEFAULT 0,
  `total_hours_worked` decimal(7,2) NOT NULL DEFAULT 0.00,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp(),
  PRIMARY KEY (`summary_id`),
  UNIQUE KEY `uniq_emp_period_summary` (`employee_id`,`period_id`),
  KEY `idx_ews_period` (`period_id`),
  CONSTRAINT `fk_ews_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ews_period` FOREIGN KEY (`period_id`) REFERENCES `tblpayroll_period` (`period_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblemployee_workday_summary` (`summary_id`,`employee_id`,`period_id`,`total_workdays`,`days_present`,`days_absent`,`days_leave`,`days_late`,`total_hours_worked`,`created_at`,`updated_at`) VALUES ('1','6','2','0','0','0','0','0','0.00','2025-08-30 08:58:51','2025-08-30 08:58:51'),
('2','3','2','0','0','0','0','0','0.00','2025-08-30 08:59:28','2025-08-30 08:59:28');

-- 
-- Structure for table `tblemployeereports`
-- 
DROP TABLE IF EXISTS `tblemployeereports`;
CREATE TABLE `tblemployeereports` (
  `Report_ID` int(11) NOT NULL AUTO_INCREMENT,
  `Employee_ID` int(11) NOT NULL,
  `Department_ID` int(11) DEFAULT NULL,
  `Position` varchar(100) DEFAULT NULL,
  `Basic_Salary` decimal(10,2) NOT NULL,
  `Status` enum('active','inactive') DEFAULT 'active',
  `Date_Hired` date DEFAULT NULL,
  `Generated_By` int(11) DEFAULT NULL,
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`Report_ID`),
  KEY `fk_er_employee` (`Employee_ID`),
  KEY `fk_er_department` (`Department_ID`),
  KEY `fk_er_generated_by` (`Generated_By`),
  CONSTRAINT `fk_er_department` FOREIGN KEY (`Department_ID`) REFERENCES `tbldepartments` (`dept_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_er_employee` FOREIGN KEY (`Employee_ID`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_er_generated_by` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 
-- Structure for table `tblemployees`
-- 
DROP TABLE IF EXISTS `tblemployees`;
CREATE TABLE `tblemployees` (
  `employee_id` int(11) NOT NULL AUTO_INCREMENT,
  `first_name` varchar(50) NOT NULL,
  `middle_name` varchar(50) DEFAULT NULL,
  `last_name` varchar(50) NOT NULL,
  `date_of_birth` date DEFAULT NULL,
  `gender` enum('male','female') DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `profile_image` longtext DEFAULT NULL,
  `address` text DEFAULT NULL,
  `department` varchar(50) DEFAULT NULL,
  `position` varchar(50) DEFAULT NULL,
  `basic_salary` decimal(10,2) NOT NULL,
  `salary_rate_type` enum('monthly','daily','hourly') DEFAULT 'monthly',
  `date_hired` date DEFAULT NULL,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`employee_id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblemployees` (`employee_id`,`first_name`,`middle_name`,`last_name`,`date_of_birth`,`gender`,`email`,`phone`,`profile_image`,`address`,`department`,`position`,`basic_salary`,`salary_rate_type`,`date_hired`,`status`,`created_at`) VALUES ('1','michael','igtos','nacaya','2025-08-20','male','michael@gmail.com','09354786152',NULL,'bonbon','Finance Department','Accountant','100000.00','monthly','2025-08-20','active','2025-08-20 17:49:09'),
('2','darwin','s','casipong','2025-08-20','male','darwin@gmail.com','09354786152',NULL,'bonbon','Marketing Department','Marketing Manager','100000.00','monthly','2025-08-20','active','2025-08-20 17:49:52'),
('3','francis Oliver','g','alaba','2025-08-20','male','frans@gmail.com','09354786152',NULL,'raagas','Retail Operations Department','Retail Supervisor','100000.00','monthly','2025-08-20','active','2025-08-20 18:15:18'),
('4','roberth','NA','namoc','2025-08-20','male','roberth@gmail.com','09354786152',NULL,'carmen','Human Resources Department','HR DIRECTOR','10000.00','monthly','2025-08-20','active','2025-08-20 18:16:29'),
('5','domingo','e','ancog','2025-08-20','male','dong@gmail.com','09354786152',NULL,'raagas','Finance Department','Accounts Receivable Clerk','10000.00','monthly','2025-08-20','active','2025-08-20 18:17:51'),
('6','mjay','igtos','nacaya','2025-08-20','male','mjay@gmail.com','09354786153',NULL,'bonbon','Warehouse Department','Warehouseman','10000.00','monthly','2025-08-20','active','2025-08-20 18:46:51'),
('8','dave','NA','angka','2025-08-20','male','dave@gmail.com','09354786152',NULL,'bonbon','Warehouse Department','Warehouseman','30000.00','monthly','2025-08-20','active','2025-08-20 19:03:06'),
('13','Angela','NA','Dela Cruz','2025-08-20','male','angle@gmail.com','09354786152',NULL,'bonbon','Retail Operations Department','Product Specialist','1000.00','monthly','2025-08-20','active','2025-08-20 19:19:48'),
('14','John','NA','Reyes','2025-08-20','male','reyes@gmail.com','09354786152',NULL,'bonbon','Retail Operations Department','Assistant Store Manager','50000.00','monthly','2025-08-20','active','2025-08-20 19:21:05'),
('15','Maria','NA','Dela Cruz','2025-08-20','female','maria@gmail.com','09354786152',NULL,'bonbon','Warehouse Department','Assistant Head','10000.00','monthly','2025-08-20','active','2025-08-20 19:24:03'),
('16','Carlo','NA','Fernandez','2025-08-20','male','carlo@gmail.com','09354786152',NULL,'bonbon','IT Department','Cybersecurity Specialist','100000.00','monthly','2025-08-20','active','2025-08-20 19:25:06'),
('18','Sofia','NA','Cruz','2025-08-20','female','sofia@gmail.com','09354786152',NULL,'bonbon','Finance Department','Accounts Payable Clerk','10000.00','monthly','2025-08-20','active','2025-08-20 19:27:21');

-- 
-- Structure for table `tblleave_cancellations`
-- 
DROP TABLE IF EXISTS `tblleave_cancellations`;
CREATE TABLE `tblleave_cancellations` (
  `cancel_id` int(11) NOT NULL AUTO_INCREMENT,
  `leave_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `cancelled_by_user_id` int(11) DEFAULT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `cancelled_at` datetime NOT NULL DEFAULT current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`cancel_id`),
  KEY `fk_lc_leave` (`leave_id`),
  KEY `fk_lc_employee` (`employee_id`),
  KEY `fk_lc_cancelled_by` (`cancelled_by_user_id`),
  CONSTRAINT `fk_lc_cancelled_by` FOREIGN KEY (`cancelled_by_user_id`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_lc_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_lc_leave` FOREIGN KEY (`leave_id`) REFERENCES `tblleaves` (`leave_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 
-- Structure for table `tblleave_types`
-- 
DROP TABLE IF EXISTS `tblleave_types`;
CREATE TABLE `tblleave_types` (
  `type_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `sort_order` int(11) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`type_id`),
  UNIQUE KEY `uniq_leave_types_name` (`name`),
  KEY `idx_leave_types_active` (`is_active`),
  KEY `idx_leave_types_sort` (`sort_order`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblleave_types` (`type_id`,`name`,`description`,`is_active`,`sort_order`,`created_at`) VALUES ('1','vacation','Paid time off for rest or personal matters','1','1','2025-08-30 07:13:39'),
('2','sick leave','Leave due to illness','1','2','2025-08-30 07:13:39'),
('3','birthday leave','Leave for birthday','1','3','2025-08-30 07:13:39'),
('4','deductible against pay','Unpaid leave, deducted from pay','1','4','2025-08-30 07:13:39'),
('5','maternity','Maternity leave','1','5','2025-08-30 07:13:39'),
('6','paternity','Paternity leave','1','6','2025-08-30 07:13:39');

-- 
-- Structure for table `tblleaves`
-- 
DROP TABLE IF EXISTS `tblleaves`;
CREATE TABLE `tblleaves` (
  `leave_id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `start_date` date NOT NULL,
  `end_date` date NOT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `leave_type` enum('vacation','sick leave','birthday leave','deductible against pay','maternity','paternity') NOT NULL DEFAULT 'vacation',
  `status` enum('pending','approved','rejected') DEFAULT 'pending',
  `approved_by` int(11) DEFAULT NULL,
  `approved_at` datetime DEFAULT NULL,
  `rejected_by` int(11) DEFAULT NULL,
  `rejected_at` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`leave_id`),
  KEY `fk_leaves_employee` (`employee_id`),
  KEY `fk_leaves_approved_by` (`approved_by`),
  KEY `fk_leaves_rejected_by` (`rejected_by`),
  CONSTRAINT `fk_leaves_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_leaves_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_leaves_rejected_by` FOREIGN KEY (`rejected_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblleaves` (`leave_id`,`employee_id`,`start_date`,`end_date`,`reason`,`leave_type`,`status`,`approved_by`,`approved_at`,`rejected_by`,`rejected_at`,`created_at`) VALUES ('1','6','2025-08-20','2025-08-20','123','deductible against pay','pending',NULL,NULL,NULL,NULL,'2025-08-20 18:50:00');

-- 
-- Structure for table `tblnotifications`
-- 
DROP TABLE IF EXISTS `tblnotifications`;
CREATE TABLE `tblnotifications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `message` varchar(255) NOT NULL,
  `type` varchar(30) DEFAULT NULL,
  `actor_user_id` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `read_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_notifications_employee` (`employee_id`),
  KEY `fk_notifications_actor` (`actor_user_id`),
  CONSTRAINT `fk_notifications_actor` FOREIGN KEY (`actor_user_id`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_notifications_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblnotifications` (`id`,`employee_id`,`message`,`type`,`actor_user_id`,`created_at`,`read_at`) VALUES ('1','6','Profile updated: Phone: 09354786152 -> 09354786153','profile_update','1','2025-08-20 18:48:46',NULL),
('2','6','Your payslip has been paid (2025-08-30 → 2025-09-30)','payslip_paid','1','2025-08-30 08:59:16',NULL);

-- 
-- Structure for table `tblovertime_requests`
-- 
DROP TABLE IF EXISTS `tblovertime_requests`;
CREATE TABLE `tblovertime_requests` (
  `ot_id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `work_date` date NOT NULL,
  `start_time` time DEFAULT NULL,
  `end_time` time DEFAULT NULL,
  `hours` decimal(5,2) DEFAULT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `status` enum('pending','approved','rejected') DEFAULT 'pending',
  `approved_by` int(11) DEFAULT NULL,
  `approved_at` datetime DEFAULT NULL,
  `rejected_by` int(11) DEFAULT NULL,
  `rejected_at` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`ot_id`),
  KEY `fk_ot_employee` (`employee_id`),
  KEY `fk_ot_approved_by` (`approved_by`),
  KEY `fk_ot_rejected_by` (`rejected_by`),
  KEY `idx_ot_employee_date` (`employee_id`,`work_date`),
  KEY `idx_ot_status` (`status`),
  CONSTRAINT `fk_ot_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_ot_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ot_rejected_by` FOREIGN KEY (`rejected_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 
-- Structure for table `tblpayroll`
-- 
DROP TABLE IF EXISTS `tblpayroll`;
CREATE TABLE `tblpayroll` (
  `payroll_id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `payroll_period_start` date NOT NULL,
  `payroll_period_end` date NOT NULL,
  `basic_salary` decimal(10,2) NOT NULL,
  `total_overtime_hours` decimal(5,2) DEFAULT 0.00,
  `overtime_pay` decimal(10,2) DEFAULT 0.00,
  `deductions` decimal(10,2) DEFAULT 0.00,
  `net_pay` decimal(10,2) NOT NULL,
  `status` enum('processed','paid') DEFAULT 'processed',
  `paid_at` datetime DEFAULT NULL,
  `paid_by` int(11) DEFAULT NULL,
  `slip_downloaded_at` datetime DEFAULT NULL,
  `slip_download_count` int(11) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`payroll_id`),
  KEY `fk_payroll_paid_by` (`paid_by`),
  KEY `idx_payroll_status` (`status`),
  KEY `idx_payroll_period` (`employee_id`,`payroll_period_start`,`payroll_period_end`),
  CONSTRAINT `fk_payroll_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_payroll_paid_by` FOREIGN KEY (`paid_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblpayroll` (`payroll_id`,`employee_id`,`payroll_period_start`,`payroll_period_end`,`basic_salary`,`total_overtime_hours`,`overtime_pay`,`deductions`,`net_pay`,`status`,`paid_at`,`paid_by`,`slip_downloaded_at`,`slip_download_count`,`created_at`) VALUES ('1','6','2025-08-30','2025-09-30','10000.00','0.00','0.00','825.00','9175.00','paid','2025-08-30 08:59:16','1',NULL,'0','2025-08-30 08:58:51'),
('2','3','2025-08-30','2025-09-30','100000.00','0.00','0.00','28183.23','71816.77','processed',NULL,NULL,NULL,'0','2025-08-30 08:59:28');

-- 
-- Structure for table `tblpayroll_period`
-- 
DROP TABLE IF EXISTS `tblpayroll_period`;
CREATE TABLE `tblpayroll_period` (
  `period_id` int(11) NOT NULL AUTO_INCREMENT,
  `period_start` date NOT NULL,
  `period_end` date NOT NULL,
  `status` enum('open','closed') DEFAULT 'open',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`period_id`),
  UNIQUE KEY `uniq_payroll_period` (`period_start`,`period_end`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblpayroll_period` (`period_id`,`period_start`,`period_end`,`status`,`created_at`) VALUES ('1','2025-08-01','2025-08-15','open','2025-08-20 17:35:05'),
('2','2025-08-30','2025-09-30','open','2025-08-30 08:58:51');

-- 
-- Structure for table `tblpayroll_slip_downloads`
-- 
DROP TABLE IF EXISTS `tblpayroll_slip_downloads`;
CREATE TABLE `tblpayroll_slip_downloads` (
  `download_id` int(11) NOT NULL AUTO_INCREMENT,
  `payroll_id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `downloaded_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`download_id`),
  KEY `fk_psd_user` (`user_id`),
  KEY `idx_psd_payroll` (`payroll_id`),
  KEY `idx_psd_downloaded_at` (`downloaded_at`),
  CONSTRAINT `fk_psd_payroll` FOREIGN KEY (`payroll_id`) REFERENCES `tblpayroll` (`payroll_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_psd_user` FOREIGN KEY (`user_id`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 
-- Structure for table `tblpayrollreports`
-- 
DROP TABLE IF EXISTS `tblpayrollreports`;
CREATE TABLE `tblpayrollreports` (
  `Report_ID` int(11) NOT NULL AUTO_INCREMENT,
  `Payroll_ID` int(11) NOT NULL,
  `Employee_ID` int(11) NOT NULL,
  `Period_Start` date NOT NULL,
  `Period_End` date NOT NULL,
  `Basic_Salary` decimal(10,2) NOT NULL,
  `Total_Allowances` decimal(10,2) DEFAULT 0.00,
  `Total_Deductions` decimal(10,2) DEFAULT 0.00,
  `Net_Pay` decimal(10,2) NOT NULL,
  `Generated_By` int(11) DEFAULT NULL,
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`Report_ID`),
  KEY `fk_pr_payroll` (`Payroll_ID`),
  KEY `fk_pr_employee` (`Employee_ID`),
  KEY `fk_pr_generated_by` (`Generated_By`),
  CONSTRAINT `fk_pr_employee` FOREIGN KEY (`Employee_ID`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_pr_generated_by` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_pr_payroll` FOREIGN KEY (`Payroll_ID`) REFERENCES `tblpayroll` (`payroll_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
INSERT INTO `tblpayrollreports` (`Report_ID`,`Payroll_ID`,`Employee_ID`,`Period_Start`,`Period_End`,`Basic_Salary`,`Total_Allowances`,`Total_Deductions`,`Net_Pay`,`Generated_By`,`Generated_At`) VALUES ('1','2','3','2025-08-30','2025-09-30','100000.00','0.00','28183.23','71816.77','1','2025-08-30 09:00:32'),
('2','2','3','2025-08-30','2025-09-30','100000.00','0.00','28183.23','71816.77','1','2025-08-30 09:00:36');

-- 
-- Structure for table `tblpayslip_history`
-- 
DROP TABLE IF EXISTS `tblpayslip_history`;
CREATE TABLE `tblpayslip_history` (
  `history_id` int(11) NOT NULL AUTO_INCREMENT,
  `payroll_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `payroll_period_start` date NOT NULL,
  `payroll_period_end` date NOT NULL,
  `basic_salary` decimal(10,2) NOT NULL,
  `total_allowances` decimal(10,2) DEFAULT 0.00,
  `total_overtime_hours` decimal(5,2) DEFAULT 0.00,
  `overtime_pay` decimal(10,2) DEFAULT 0.00,
  `total_deductions` decimal(10,2) DEFAULT 0.00,
  `net_pay` decimal(10,2) NOT NULL,
  `snapshot_details` longtext DEFAULT NULL,
  `file_path` varchar(255) DEFAULT NULL,
  `generated_by` int(11) DEFAULT NULL,
  `generated_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`history_id`),
  UNIQUE KEY `uniq_payslip_per_payroll_employee` (`payroll_id`,`employee_id`),
  KEY `idx_ph_payroll` (`payroll_id`),
  KEY `idx_ph_employee` (`employee_id`),
  KEY `idx_ph_generated_at` (`generated_at`),
  KEY `fk_ph_generated_by` (`generated_by`),
  CONSTRAINT `fk_ph_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ph_generated_by` FOREIGN KEY (`generated_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_ph_payroll` FOREIGN KEY (`payroll_id`) REFERENCES `tblpayroll` (`payroll_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 
-- Structure for table `tblsystem_settings`
-- 
DROP TABLE IF EXISTS `tblsystem_settings`;
CREATE TABLE `tblsystem_settings` (
  `setting_key` varchar(100) NOT NULL,
  `setting_value` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblsystem_settings` (`setting_key`,`setting_value`,`updated_at`) VALUES ('absent_deduction_enabled','1','2025-08-20 17:35:06'),
('account_allow_admin_unblock','1','2025-08-20 17:35:06'),
('account_lock_enabled','0','2025-08-20 17:35:06'),
('account_lock_max_attempts','5','2025-08-20 17:35:06'),
('account_lock_window_minutes','15','2025-08-20 17:35:06'),
('account_lockout_duration_minutes','0','2025-08-30 07:16:00'),
('account_lockout_escalation_attempts_enabled','1','2025-08-30 07:16:00'),
('account_lockout_escalation_enabled','1','2025-08-30 07:16:00'),
('account_lockout_first_attempts','3','2025-08-30 07:16:00'),
('account_lockout_first_minutes','1','2025-08-30 07:16:00'),
('account_lockout_minutes','30','2025-08-20 17:35:06'),
('account_lockout_second_attempts','3','2025-08-30 07:16:00'),
('account_lockout_second_minutes','2','2025-08-30 07:16:00'),
('account_lockout_third_attempts','3','2025-08-30 07:16:00'),
('account_lockout_third_minutes','3','2025-08-30 07:16:00'),
('account_lockout_threshold','0','2025-08-30 07:16:00'),
('company_name','My Company','2025-08-20 17:35:06'),
('cutoff_1_end','15','2025-08-20 17:35:06'),
('cutoff_1_start','1','2025-08-20 17:35:06'),
('cutoff_2_end','last_day','2025-08-20 17:35:06'),
('cutoff_2_start','16','2025-08-20 17:35:06'),
('default_sick_days','5','2025-08-20 17:35:06'),
('default_vacation_days','5','2025-08-20 17:35:06'),
('grace_period_minutes','0','2025-08-20 17:35:06'),
('late_deduction_enabled','1','2025-08-20 17:35:06'),
('lunch_hours_per_day','1','2025-08-20 17:35:06'),
('overtime_multiplier','1.25','2025-08-20 17:35:06'),
('password_expiry_days','0','2025-08-30 07:16:00'),
('password_min_length','8','2025-08-30 07:16:00'),
('password_require_number','1','2025-08-30 07:16:00'),
('password_require_special','0','2025-08-30 07:16:00'),
('password_require_uppercase','1','2025-08-30 07:16:00'),
('payroll_currency','PHP','2025-08-20 17:35:06'),
('remember_me_enabled','0','2025-08-30 07:16:00'),
('rounding_interval_minutes','0','2025-08-20 17:35:06'),
('session_timeout_minutes','30','2025-08-30 09:20:58'),
('two_factor_enabled','0','2025-08-30 07:16:00'),
('ui_theme','teal','2025-08-30 07:15:18'),
('ui_theme_primary_600','#0d9488','2025-08-30 07:15:18'),
('ui_theme_primary_700','#0f766e','2025-08-30 07:15:18'),
('undertime_deduction_enabled','1','2025-08-20 17:35:06'),
('undertime_deduction_per_hour','100.00','2025-08-20 17:35:06'),
('work_hours_per_day','12','2025-08-20 17:35:06');

-- 
-- Structure for table `tblundertime_requests`
-- 
DROP TABLE IF EXISTS `tblundertime_requests`;
CREATE TABLE `tblundertime_requests` (
  `ut_id` int(11) NOT NULL AUTO_INCREMENT,
  `employee_id` int(11) NOT NULL,
  `work_date` date NOT NULL,
  `hours` decimal(5,2) NOT NULL,
  `start_time` time DEFAULT NULL,
  `end_time` time DEFAULT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `status` enum('pending','approved','rejected') DEFAULT 'pending',
  `approved_by` int(11) DEFAULT NULL,
  `approved_at` datetime DEFAULT NULL,
  `rejected_by` int(11) DEFAULT NULL,
  `rejected_at` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`ut_id`),
  KEY `fk_ut_employee` (`employee_id`),
  KEY `fk_ut_approved_by` (`approved_by`),
  KEY `fk_ut_rejected_by` (`rejected_by`),
  KEY `idx_ut_employee_date` (`employee_id`,`work_date`),
  KEY `idx_ut_status` (`status`),
  CONSTRAINT `fk_ut_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_ut_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ut_rejected_by` FOREIGN KEY (`rejected_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 
-- Structure for table `tblusers`
-- 
DROP TABLE IF EXISTS `tblusers`;
CREATE TABLE `tblusers` (
  `user_id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','employee','manager','hr') NOT NULL,
  `employee_id` int(11) DEFAULT NULL,
  `avatar_url` varchar(255) DEFAULT NULL,
  `reset_code` varchar(6) DEFAULT NULL,
  `reset_code_expires` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `username` (`username`),
  KEY `fk_users_employee` (`employee_id`),
  CONSTRAINT `fk_users_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT INTO `tblusers` (`user_id`,`username`,`password`,`role`,`employee_id`,`avatar_url`,`reset_code`,`reset_code_expires`,`created_at`) VALUES ('1','admin','$2y$10$tfTFmZPsCEsg4uuCBDNuvu2zRUmwoVabSssOrFcCnDUuQ9gbYcxcC','admin',NULL,NULL,NULL,NULL,'2025-08-20 17:42:06'),
('2','hr','$2y$10$T4/xf6s7dyGu7cwLPYJi2ecYxlnBdBRhsyVfkcZiNVqxaoP7m0AQq','hr',NULL,NULL,NULL,NULL,'2025-08-20 17:42:06'),
('3','michael@gmail.com','$2y$10$OOH9KvBaZ7C7JzX9ms0j7uthFnta4Xp0EVCg/MlNPDXO1701oa1UO','manager','1',NULL,NULL,NULL,'2025-08-20 17:49:09'),
('4','darwin@gmail.com','$2y$10$lElhsaLQlifIxX9TXR9MKeR9wKFhsv9qAURullUmWGUfzcL77KJ.S','manager','2',NULL,NULL,NULL,'2025-08-20 17:49:52'),
('5','frans@gmail.com','$2y$10$K//Q0crkOndyxMh0C/OxAei/mIOAiTHigmvl91HDk/BgEQES3B29e','manager','3',NULL,NULL,NULL,'2025-08-20 18:15:18'),
('6','roberth@gmail.com','$2y$10$NoKY5JWM7VATnxxfUgz1KOI4wsdlIxwSY2KocWHJJSEMCQsihFLze','hr','4',NULL,NULL,NULL,'2025-08-20 18:16:29'),
('7','dong@gmail.com','$2y$10$TEMI8aKaE3.dUi51FKURcudqYYCeUsI2NhA2eiSD26.zBsKnyb6LC','employee','5',NULL,NULL,NULL,'2025-08-20 18:17:51'),
('9','mjay@gmail.com','$2y$10$.9p.Pxy4hA5QdbadVs5hLu5rs7GSRYL0scf9M4eqJAiOyLcH378wu','employee','6',NULL,NULL,NULL,'2025-08-20 18:48:15'),
('11','dave@gmail.com','$2y$10$LB3I38FbIAXTWW/m4rEME.r24fiDYaYv1rF73h/ja4K7jxJU/zLbW','employee','8',NULL,NULL,NULL,'2025-08-20 19:03:06'),
('12','angle@gmail.com','$2y$10$/uQQerOin0fxGhXZB9/bee7blFO6/eEmhT2DgjpMXoXr/Vfbvo.y6','employee','13',NULL,NULL,NULL,'2025-08-20 19:19:48'),
('13','reyes@gmail.com','$2y$10$ZcsP14vChRDUKY28WIuz2.yExYsYPhaLEFiN8H83Fqvx54OB78vfO','employee','14',NULL,NULL,NULL,'2025-08-20 19:21:05'),
('14','maria@gmail.com','$2y$10$KwOpkSbKzJzLKCluWpTgTuBNGH.oemYO8uQzc55ZtLYBUcrUg07A.','manager','15',NULL,NULL,NULL,'2025-08-20 19:24:03'),
('15','carlo@gmail.com','$2y$10$3WBnPrwZHUEJcFxHBoCe.OTmy2ACEHDYC6SCwbsEfPIj3IJbwDegm','manager','16',NULL,NULL,NULL,'2025-08-20 19:25:06'),
('16','sofia@gmail.com','$2y$10$vNSdOYl7Q4ECDXrVZuxcfuWo5yRYT1F1WhFRagEVwGPL9mx6HHGUe','employee','18',NULL,NULL,NULL,'2025-08-20 19:27:21');
COMMIT;
SET FOREIGN_KEY_CHECKS=1;