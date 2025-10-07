-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Sep 09, 2025 at 02:16 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `dbattendance`
--

-- --------------------------------------------------------

--
-- Table structure for table `tblattendance`
--

CREATE TABLE `tblattendance` (
  `attendance_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `attendance_date` date NOT NULL,
  `time_in` time DEFAULT NULL,
  `time_out` time DEFAULT NULL,
  `status` enum('present','absent','leave','late','undertime') DEFAULT 'present',
  `remarks` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblattendancereports`
--

CREATE TABLE `tblattendancereports` (
  `Report_ID` int(11) NOT NULL,
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
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblattendance_daily_summary`
--

CREATE TABLE `tblattendance_daily_summary` (
  `summary_id` int(11) NOT NULL,
  `summary_date` date NOT NULL,
  `total_present` int(11) DEFAULT 0,
  `total_absent` int(11) DEFAULT 0,
  `total_late` int(11) DEFAULT 0,
  `total_leave` int(11) DEFAULT 0,
  `total_undertime` int(11) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblattendance_employee_daily`
--

CREATE TABLE `tblattendance_employee_daily` (
  `id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `attendance_date` date NOT NULL,
  `status` enum('present','absent','leave','late','undertime') NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblaudit_logs`
--

CREATE TABLE `tblaudit_logs` (
  `log_id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(255) NOT NULL,
  `details` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tblaudit_logs`
--

INSERT INTO `tblaudit_logs` (`log_id`, `user_id`, `action`, `details`, `ip_address`, `created_at`) VALUES
(1, 1, 'login', 'User admin logged in successfully', '::1', '2025-08-20 09:42:11'),
(2, 1, 'logout', 'User admin logged out', '::1', '2025-08-20 10:49:37'),
(3, 9, 'login', 'User mjay@gmail.com logged in successfully', '::1', '2025-08-20 10:49:46'),
(4, 9, 'logout', 'User mjay@gmail.com logged out', '::1', '2025-08-20 10:50:05'),
(5, 1, 'login', 'User admin logged in successfully', '::1', '2025-08-20 10:50:09'),
(6, 1, 'logout', 'User admin logged out', '::1', '2025-08-20 10:51:04'),
(7, 1, 'login', 'User admin logged in successfully', '::1', '2025-08-20 10:51:09'),
(8, 1, 'login', 'User admin logged in successfully', '::1', '2025-08-20 11:00:57'),
(9, 1, 'logout', 'User admin logged out', '::1', '2025-08-20 11:29:39'),
(10, 14, 'login', 'User maria@gmail.com logged in successfully', '::1', '2025-08-20 11:30:23'),
(11, 14, 'logout', 'User maria@gmail.com logged out', '::1', '2025-08-20 11:36:40'),
(12, 3, 'login', 'User michael@gmail.com logged in successfully', '::1', '2025-08-20 11:36:49'),
(13, 3, 'logout', 'User michael@gmail.com logged out', '::1', '2025-08-20 11:36:52'),
(14, 14, 'login', 'User maria@gmail.com logged in successfully', '::1', '2025-08-20 11:37:10'),
(15, 14, 'login', 'User maria@gmail.com logged in successfully', '::1', '2025-08-20 11:39:41'),
(16, 14, 'logout', 'User maria@gmail.com logged out', '::1', '2025-08-20 11:45:18'),
(17, 1, 'login', 'User admin logged in successfully', '::1', '2025-08-20 11:45:24'),
(18, 1, 'login', 'User admin logged in successfully', '::1', '2025-09-08 23:55:02'),
(19, 1, 'logout', 'User admin logged out', '::1', '2025-09-08 23:55:32'),
(20, 1, 'login', 'User admin logged in successfully', '::1', '2025-09-08 23:57:04'),
(21, 1, 'logout', 'User admin logged out', '::1', '2025-09-08 23:57:40');

-- --------------------------------------------------------

--
-- Table structure for table `tbldeductionreports`
--

CREATE TABLE `tbldeductionreports` (
  `Report_ID` int(11) NOT NULL,
  `Deduction_ID` int(11) NOT NULL,
  `Employee_ID` int(11) NOT NULL,
  `Payroll_ID` int(11) DEFAULT NULL,
  `Deduction_Amount` decimal(10,2) DEFAULT 0.00,
  `Period_Start` date DEFAULT NULL,
  `Period_End` date DEFAULT NULL,
  `Generated_By` int(11) DEFAULT NULL,
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbldeductions`
--

CREATE TABLE `tbldeductions` (
  `deduct_id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `amount` decimal(12,2) DEFAULT 0.00,
  `amount_type` enum('fixed','percent') DEFAULT 'fixed',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tbldeductions`
--

INSERT INTO `tbldeductions` (`deduct_id`, `name`, `description`, `amount`, `amount_type`, `created_at`) VALUES
(1, 'SSS', 'Social Security System', 5.00, 'percent', '2025-08-20 09:35:06'),
(2, 'PhilHealth', 'PhilHealth contribution', 300.00, 'fixed', '2025-08-20 09:35:06'),
(3, 'Pag-IBIG', 'Pag-IBIG (HDMF) contribution', 0.00, 'fixed', '2025-08-20 09:35:06'),
(4, 'Withholding Tax', 'Income tax withholding', 0.00, 'fixed', '2025-08-20 09:35:06'),
(5, 'Provident Fund', 'Provident Fund contribution', 10.00, 'percent', '2025-08-20 09:35:06');

-- --------------------------------------------------------

--
-- Table structure for table `tbldepartmentreports`
--

CREATE TABLE `tbldepartmentreports` (
  `Report_ID` int(11) NOT NULL,
  `Department_ID` int(11) NOT NULL,
  `Total_Employees` int(11) DEFAULT 0,
  `Total_Salary` decimal(12,2) DEFAULT 0.00,
  `Generated_By` int(11) DEFAULT NULL,
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbldepartments`
--

CREATE TABLE `tbldepartments` (
  `dept_id` int(11) NOT NULL,
  `dept_name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tbldepartments`
--

INSERT INTO `tbldepartments` (`dept_id`, `dept_name`, `description`, `created_at`) VALUES
(1, 'Finance Department', 'Handles company finances', '2025-08-20 09:35:05'),
(2, 'Human Resources Department', 'Oversees people operations', '2025-08-20 09:35:05'),
(3, 'IT Department', 'Manages company IT systems', '2025-08-20 09:35:05'),
(4, 'Marketing Department', 'Handles marketing and promotions', '2025-08-20 09:35:05'),
(5, 'Retail Operations Department', 'Manages retail store operations', '2025-08-20 09:35:05'),
(6, 'Warehouse Department', 'Oversees storage and inventory management', '2025-08-20 09:35:05');

-- --------------------------------------------------------

--
-- Table structure for table `tbldepartment_positions`
--

CREATE TABLE `tbldepartment_positions` (
  `id` int(11) NOT NULL,
  `dept_id` int(11) NOT NULL,
  `position_name` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tbldepartment_positions`
--

INSERT INTO `tbldepartment_positions` (`id`, `dept_id`, `position_name`) VALUES
(5, 1, 'Accountant'),
(6, 1, 'Accounts Payable Clerk'),
(7, 1, 'Accounts Receivable Clerk'),
(8, 1, 'Cash Handling Specialist'),
(9, 1, 'Payroll Specialist'),
(25, 2, 'HR DIRECTOR'),
(21, 3, 'Cybersecurity Specialist'),
(22, 3, 'Database Administrator'),
(23, 3, 'System Administrator'),
(24, 3, 'Web Developer'),
(1, 4, 'Content Writer'),
(2, 4, 'Event Coordinator'),
(3, 4, 'Marketing Manager'),
(4, 4, 'Social Media Specialist'),
(15, 5, 'Assistant Store Manager'),
(16, 5, 'Bagger'),
(17, 5, 'Cashier'),
(18, 5, 'Product Specialist'),
(19, 5, 'Retail Supervisor'),
(20, 5, 'Store Manager'),
(10, 6, 'Assistant Head'),
(11, 6, 'Diser'),
(12, 6, 'Head'),
(13, 6, 'Merchandiser'),
(14, 6, 'Warehouseman');

-- --------------------------------------------------------

--
-- Table structure for table `tblemployeereports`
--

CREATE TABLE `tblemployeereports` (
  `Report_ID` int(11) NOT NULL,
  `Employee_ID` int(11) NOT NULL,
  `Department_ID` int(11) DEFAULT NULL,
  `Position` varchar(100) DEFAULT NULL,
  `Basic_Salary` decimal(10,2) NOT NULL,
  `Status` enum('active','inactive') DEFAULT 'active',
  `Date_Hired` date DEFAULT NULL,
  `Generated_By` int(11) DEFAULT NULL,
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblemployees`
--

CREATE TABLE `tblemployees` (
  `employee_id` int(11) NOT NULL,
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
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tblemployees`
--

INSERT INTO `tblemployees` (`employee_id`, `first_name`, `middle_name`, `last_name`, `date_of_birth`, `gender`, `email`, `phone`, `profile_image`, `address`, `department`, `position`, `basic_salary`, `salary_rate_type`, `date_hired`, `status`, `created_at`) VALUES
(1, 'michael', 'igtos', 'nacaya', '2025-08-20', 'male', 'michaelnacaya86@gmail.com', '09354786152', NULL, 'bonbon', 'Finance Department', 'Accountant', 100000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 09:49:09'),
(2, 'darwin', 's', 'casipong', '2025-08-20', 'male', 'darwin@gmail.com', '09354786152', NULL, 'bonbon', 'Marketing Department', 'Marketing Manager', 100000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 09:49:52'),
(3, 'francis Oliver', 'g', 'alaba', '2025-08-20', 'male', 'frans@gmail.com', '09354786152', NULL, 'raagas', 'Retail Operations Department', 'Retail Supervisor', 100000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 10:15:18'),
(4, 'roberth', 'NA', 'namoc', '2025-08-20', 'male', 'roberth@gmail.com', '09354786152', NULL, 'carmen', 'Human Resources Department', 'HR DIRECTOR', 10000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 10:16:29'),
(5, 'domingo', 'e', 'ancog', '2025-08-20', 'male', 'dong@gmail.com', '09354786152', NULL, 'raagas', 'Finance Department', 'Accounts Receivable Clerk', 10000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 10:17:51'),
(6, 'mjay', 'igtos', 'nacaya', '2025-08-20', 'male', 'mjay@gmail.com', '09354786153', NULL, 'bonbon', 'Warehouse Department', 'Warehouseman', 10000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 10:46:51'),
(8, 'dave', 'NA', 'angka', '2025-08-20', 'male', 'dave@gmail.com', '09354786152', NULL, 'bonbon', 'Warehouse Department', 'Warehouseman', 30000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 11:03:06'),
(13, 'Angela', 'NA', 'Dela Cruz', '2025-08-20', 'male', 'angle@gmail.com', '09354786152', NULL, 'bonbon', 'Retail Operations Department', 'Product Specialist', 1000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 11:19:48'),
(14, 'John', 'NA', 'Reyes', '2025-08-20', 'male', 'reyes@gmail.com', '09354786152', NULL, 'bonbon', 'Retail Operations Department', 'Assistant Store Manager', 50000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 11:21:05'),
(15, 'Maria', 'NA', 'Dela Cruz', '2025-08-20', 'female', 'maria@gmail.com', '09354786152', NULL, 'bonbon', 'Warehouse Department', 'Assistant Head', 10000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 11:24:03'),
(16, 'Carlo', 'NA', 'Fernandez', '2025-08-20', 'male', 'carlo@gmail.com', '09354786152', NULL, 'bonbon', 'IT Department', 'Cybersecurity Specialist', 100000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 11:25:06'),
(18, 'Sofia', 'NA', 'Cruz', '2025-08-20', 'female', 'sofia@gmail.com', '09354786152', NULL, 'bonbon', 'Finance Department', 'Accounts Payable Clerk', 10000.00, 'monthly', '2025-08-20', 'active', '2025-08-20 11:27:21');

-- --------------------------------------------------------

--
-- Table structure for table `tblemployee_deductions`
--

CREATE TABLE `tblemployee_deductions` (
  `emp_deduct_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `deduct_id` int(11) NOT NULL,
  `value` decimal(12,2) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblemployee_financial_details`
--

CREATE TABLE `tblemployee_financial_details` (
  `fin_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `bank_account` varchar(100) DEFAULT NULL,
  `tax_id` varchar(50) DEFAULT NULL,
  `sss_number` varchar(50) DEFAULT NULL,
  `philhealth_number` varchar(50) DEFAULT NULL,
  `pagibig_number` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tblemployee_financial_details`
--

INSERT INTO `tblemployee_financial_details` (`fin_id`, `employee_id`, `bank_account`, `tax_id`, `sss_number`, `philhealth_number`, `pagibig_number`, `created_at`) VALUES
(1, 1, '', '', '', '', '', '2025-08-20 09:49:09'),
(2, 2, '', '', '', '50000', '', '2025-08-20 09:49:52'),
(3, 3, '', '', '', '555555', '', '2025-08-20 10:15:18'),
(4, 4, '', '', '', '555555', '', '2025-08-20 10:16:29'),
(5, 5, '', '', '555555', '', '', '2025-08-20 10:17:51'),
(7, 6, '', '111111', '', '', '', '2025-08-20 10:46:51'),
(14, 8, '', '5555555', '', '', '', '2025-08-20 11:03:06'),
(15, 13, '', '5555555', '', '', '', '2025-08-20 11:19:48'),
(16, 14, '', '5555555', '', '', '', '2025-08-20 11:21:05'),
(17, 15, '', '', '', '5555', '', '2025-08-20 11:24:03'),
(18, 16, '', '', '5555555', '', '', '2025-08-20 11:25:06'),
(19, 18, '', '5555555', '', '', '', '2025-08-20 11:27:21');

-- --------------------------------------------------------

--
-- Table structure for table `tblemployee_workday_summary`
--

CREATE TABLE `tblemployee_workday_summary` (
  `summary_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `period_id` int(11) NOT NULL,
  `total_workdays` int(11) NOT NULL DEFAULT 0,
  `days_present` int(11) NOT NULL DEFAULT 0,
  `days_absent` int(11) NOT NULL DEFAULT 0,
  `days_leave` int(11) NOT NULL DEFAULT 0,
  `days_late` int(11) NOT NULL DEFAULT 0,
  `total_hours_worked` decimal(7,2) NOT NULL DEFAULT 0.00,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblholidays`
--

CREATE TABLE `tblholidays` (
  `id` int(11) NOT NULL,
  `holiday_date` date NOT NULL,
  `holiday_name` varchar(100) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `is_recurring` tinyint(1) NOT NULL DEFAULT 0 COMMENT '1 if holiday repeats every year, 0 if one-time only',
  `original_date` date DEFAULT NULL COMMENT 'Original date when recurring holiday was first created (for reference)'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblleaves`
--

CREATE TABLE `tblleaves` (
  `leave_id` int(11) NOT NULL,
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
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblleave_archive`
--

CREATE TABLE `tblleave_archive` (
  `archive_id` int(11) NOT NULL,
  `leave_id` int(11) NOT NULL,
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
  `created_at` timestamp NULL DEFAULT NULL,
  `archived_reason` varchar(255) DEFAULT NULL,
  `archived_by` int(11) DEFAULT NULL,
  `archived_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblleave_cancellations`
--

CREATE TABLE `tblleave_cancellations` (
  `cancel_id` int(11) NOT NULL,
  `leave_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `cancelled_by_user_id` int(11) DEFAULT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `cancelled_at` datetime NOT NULL DEFAULT current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblleave_types`
--

CREATE TABLE `tblleave_types` (
  `type_id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `sort_order` int(11) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tblleave_types`
--

INSERT INTO `tblleave_types` (`type_id`, `name`, `description`, `is_active`, `sort_order`, `created_at`) VALUES
(1, 'vacation', 'Paid time off for rest or personal matters', 1, 1, '2025-09-08 23:54:20'),
(2, 'sick leave', 'Leave due to illness', 1, 2, '2025-09-08 23:54:20'),
(3, 'birthday leave', 'Leave for birthday', 1, 3, '2025-09-08 23:54:20'),
(4, 'deductible against pay', 'Unpaid leave, deducted from pay', 1, 4, '2025-09-08 23:54:20'),
(5, 'maternity', 'Maternity leave', 1, 5, '2025-09-08 23:54:20'),
(6, 'paternity', 'Paternity leave', 1, 6, '2025-09-08 23:54:20');

-- --------------------------------------------------------

--
-- Table structure for table `tblnotifications`
--

CREATE TABLE `tblnotifications` (
  `id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `message` varchar(255) NOT NULL,
  `type` varchar(30) DEFAULT NULL,
  `actor_user_id` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `read_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tblnotifications`
--

INSERT INTO `tblnotifications` (`id`, `employee_id`, `message`, `type`, `actor_user_id`, `created_at`, `read_at`) VALUES
(1, 6, 'Profile updated: Phone: 09354786152 -> 09354786153', 'profile_update', 1, '2025-08-20 10:48:46', NULL),
(2, 1, 'Profile updated: Email: michael@gmail.com -> michaelnacaya86@gmail.com', 'profile_update', 1, '2025-09-08 23:55:28', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `tblovertime_requests`
--

CREATE TABLE `tblovertime_requests` (
  `ot_id` int(11) NOT NULL,
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
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblpayroll`
--

CREATE TABLE `tblpayroll` (
  `payroll_id` int(11) NOT NULL,
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
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblpayrollreports`
--

CREATE TABLE `tblpayrollreports` (
  `Report_ID` int(11) NOT NULL,
  `Payroll_ID` int(11) NOT NULL,
  `Employee_ID` int(11) NOT NULL,
  `Period_Start` date NOT NULL,
  `Period_End` date NOT NULL,
  `Basic_Salary` decimal(10,2) NOT NULL,
  `Total_Deductions` decimal(10,2) DEFAULT 0.00,
  `Net_Pay` decimal(10,2) NOT NULL,
  `Generated_By` int(11) DEFAULT NULL,
  `Generated_At` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblpayroll_archive`
--

CREATE TABLE `tblpayroll_archive` (
  `archive_id` int(11) NOT NULL,
  `payroll_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `payroll_period_start` date NOT NULL,
  `payroll_period_end` date NOT NULL,
  `basic_salary` decimal(10,2) NOT NULL,
  `total_overtime_hours` decimal(5,2) DEFAULT 0.00,
  `overtime_pay` decimal(10,2) DEFAULT 0.00,
  `total_deductions` decimal(10,2) DEFAULT 0.00,
  `net_pay` decimal(10,2) NOT NULL,
  `status` enum('processed','paid') DEFAULT 'processed',
  `archived_reason` varchar(255) DEFAULT NULL,
  `archived_by` int(11) DEFAULT NULL,
  `archived_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblpayroll_period`
--

CREATE TABLE `tblpayroll_period` (
  `period_id` int(11) NOT NULL,
  `period_start` date NOT NULL,
  `period_end` date NOT NULL,
  `status` enum('open','closed') DEFAULT 'open',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tblpayroll_period`
--

INSERT INTO `tblpayroll_period` (`period_id`, `period_start`, `period_end`, `status`, `created_at`) VALUES
(1, '2025-08-01', '2025-08-15', 'open', '2025-08-20 09:35:05');

-- --------------------------------------------------------

--
-- Table structure for table `tblpayroll_slip_downloads`
--

CREATE TABLE `tblpayroll_slip_downloads` (
  `download_id` int(11) NOT NULL,
  `payroll_id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `downloaded_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblpayslip_history`
--

CREATE TABLE `tblpayslip_history` (
  `history_id` int(11) NOT NULL,
  `payroll_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `payroll_period_start` date NOT NULL,
  `payroll_period_end` date NOT NULL,
  `basic_salary` decimal(10,2) NOT NULL,
  `total_overtime_hours` decimal(5,2) DEFAULT 0.00,
  `overtime_pay` decimal(10,2) DEFAULT 0.00,
  `total_deductions` decimal(10,2) DEFAULT 0.00,
  `net_pay` decimal(10,2) NOT NULL,
  `snapshot_details` longtext DEFAULT NULL,
  `file_path` varchar(255) DEFAULT NULL,
  `generated_by` int(11) DEFAULT NULL,
  `generated_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblpayroll_by_batch`
--

CREATE TABLE `tblpayroll_by_batch` (
  `batch_id` int(11) NOT NULL,
  `batch_name` varchar(100) NOT NULL,
  `payroll_period_start` date NOT NULL,
  `payroll_period_end` date NOT NULL,
  `department` varchar(100) DEFAULT NULL,
  `total_employees` int(11) DEFAULT 0,
  `total_amount` decimal(12,2) DEFAULT 0.00,
  `status` enum('pending','processing','completed','failed') DEFAULT 'pending',
  `notes` text DEFAULT NULL,
  `generated_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblpayroll_batch_employees`
--

CREATE TABLE `tblpayroll_batch_employees` (
  `batch_emp_id` int(11) NOT NULL,
  `batch_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `basic_salary` decimal(10,2) NOT NULL,
  `overtime_pay` decimal(10,2) DEFAULT 0.00,
  `deductions` decimal(10,2) DEFAULT 0.00,
  `net_pay` decimal(10,2) NOT NULL,
  `status` enum('pending','processed','paid') DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblnotification_templates`
--

CREATE TABLE `tblnotification_templates` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `type` varchar(50) NOT NULL,
  `recipients` varchar(100) NOT NULL,
  `subject` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `priority` enum('low','normal','high','urgent') DEFAULT 'normal',
  `delivery_method` enum('in_app','email','sms','all') DEFAULT 'in_app',
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblsystem_settings`
--

CREATE TABLE `tblsystem_settings` (
  `setting_key` varchar(100) NOT NULL,
  `setting_value` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tblsystem_settings`
--

INSERT INTO `tblsystem_settings` (`setting_key`, `setting_value`, `updated_at`) VALUES
('absent_deduction_enabled', '1', '2025-09-08 23:54:20'),
('absent_deduction_per_day', '0', '2025-09-08 23:54:20'),
('account_allow_admin_unblock', '1', '2025-09-08 23:54:20'),
('account_lock_enabled', '0', '2025-09-08 23:54:20'),
('account_lock_max_attempts', '5', '2025-09-08 23:54:20'),
('account_lock_window_minutes', '15', '2025-09-08 23:54:20'),
('account_lockout_minutes', '30', '2025-09-08 23:54:20'),
('allow_break_scans', '1', '2025-09-08 23:54:20'),
('clock_in_method', 'qr', '2025-09-08 23:54:20'),
('company_address', '2nd Floor, Ipil Street, Carmen, Cagayan de Oro City, Misamis Oriental, Philippines 9000', '2025-09-08 23:57:37'),
('company_name', 'Unitop', '2025-09-08 23:57:37'),
('default_sick_days', '5', '2025-09-08 23:54:20'),
('default_vacation_days', '5', '2025-09-08 23:54:20'),
('developed_by', '', '2025-09-08 23:54:20'),
('grace_period_minutes', '0', '2025-09-08 23:54:20'),
('late_deduction_enabled', '1', '2025-09-08 23:54:20'),
('late_deduction_per_minute', '0', '2025-09-08 23:54:20'),
('loans_enabled', '1', '2025-09-08 23:54:20'),
('lunch_hours_per_day', '1', '2025-09-08 23:54:20'),
('notify_delivery_option', 'in_app', '2025-09-08 23:54:20'),
('notify_message', '', '2025-09-08 23:54:20'),
('notify_recipient', '', '2025-09-08 23:54:20'),
('notify_recipients', '', '2025-09-08 23:54:20'),
('notify_type', 'general', '2025-09-08 23:54:20'),
('ot_regular_holiday_multiplier', '2.00', '2025-09-08 23:54:20'),
('ot_regular_multiplier', '1.25', '2025-09-08 23:54:20'),
('ot_rest_day_multiplier', '1.30', '2025-09-08 23:54:20'),
('ot_special_holiday_multiplier', '1.50', '2025-09-08 23:54:20'),
('overtime_multiplier', '1.25', '2025-09-08 23:54:20'),
('overtime_tracking_enabled', '1', '2025-09-08 23:54:20'),
('pagibig_enabled', '1', '2025-09-08 23:54:20'),
('pay_period', 'semi_monthly', '2025-09-08 23:54:20'),
('payroll_currency', 'PHP', '2025-09-08 23:54:20'),
('philhealth_enabled', '1', '2025-09-08 23:54:20'),
('rounding_interval_minutes', '0', '2025-09-08 23:54:20'),
('salary_basis', 'monthly', '2025-09-08 23:54:20'),
('sss_enabled', '1', '2025-09-08 23:54:20'),
('standard_work_end_time', '17:00', '2025-09-08 23:54:20'),
('standard_work_start_time', '08:00', '2025-09-08 23:54:20'),
('system_profile', 'production', '2025-09-08 23:54:20'),
('tax_enabled', '1', '2025-09-08 23:54:20'),
('ui_theme', 'blue', '2025-09-08 23:54:20'),
('ui_theme_primary_600', '#2563eb', '2025-09-08 23:54:20'),
('ui_theme_primary_700', '#1d4ed8', '2025-09-08 23:54:20'),
('undertime_deduction_enabled', '1', '2025-09-08 23:54:20'),
('undertime_deduction_per_hour', '100.00', '2025-09-08 23:54:20'),
('undertime_grace_minutes', '0', '2025-09-08 23:54:20'),
('work_hours_per_day', '12', '2025-09-08 23:54:20'),
('work_week', '[\"mon\",\"tue\",\"wed\",\"thu\",\"fri\"]', '2025-09-08 23:54:20');

-- --------------------------------------------------------

--
-- Table structure for table `tblundertime_requests`
--

CREATE TABLE `tblundertime_requests` (
  `ut_id` int(11) NOT NULL,
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
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tblusers`
--

CREATE TABLE `tblusers` (
  `user_id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','employee','manager','hr') NOT NULL,
  `employee_id` int(11) DEFAULT NULL,
  `avatar_url` varchar(255) DEFAULT NULL,
  `reset_code` varchar(6) DEFAULT NULL,
  `reset_code_expires` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `tblusers`
--

INSERT INTO `tblusers` (`user_id`, `username`, `password`, `role`, `employee_id`, `avatar_url`, `reset_code`, `reset_code_expires`, `created_at`) VALUES
(1, 'admin', '$2y$10$tfTFmZPsCEsg4uuCBDNuvu2zRUmwoVabSssOrFcCnDUuQ9gbYcxcC', 'admin', NULL, NULL, NULL, NULL, '2025-08-20 09:42:06'),
(2, 'hr', '$2y$10$T4/xf6s7dyGu7cwLPYJi2ecYxlnBdBRhsyVfkcZiNVqxaoP7m0AQq', 'hr', NULL, NULL, NULL, NULL, '2025-08-20 09:42:06'),
(3, 'michaelnacaya86@gmail.com', '$2y$10$To85lu1W3W4oEMr1dEAryOvESYQUjwHG1jxREXb9rH5i1cTMajYue', 'manager', 1, NULL, NULL, NULL, '2025-08-20 09:49:09'),
(4, 'darwin@gmail.com', '$2y$10$lElhsaLQlifIxX9TXR9MKeR9wKFhsv9qAURullUmWGUfzcL77KJ.S', 'manager', 2, NULL, NULL, NULL, '2025-08-20 09:49:52'),
(5, 'frans@gmail.com', '$2y$10$K//Q0crkOndyxMh0C/OxAei/mIOAiTHigmvl91HDk/BgEQES3B29e', 'manager', 3, NULL, NULL, NULL, '2025-08-20 10:15:18'),
(6, 'roberth@gmail.com', '$2y$10$NoKY5JWM7VATnxxfUgz1KOI4wsdlIxwSY2KocWHJJSEMCQsihFLze', 'hr', 4, NULL, NULL, NULL, '2025-08-20 10:16:29'),
(7, 'dong@gmail.com', '$2y$10$TEMI8aKaE3.dUi51FKURcudqYYCeUsI2NhA2eiSD26.zBsKnyb6LC', 'employee', 5, NULL, NULL, NULL, '2025-08-20 10:17:51'),
(9, 'mjay@gmail.com', '$2y$10$.9p.Pxy4hA5QdbadVs5hLu5rs7GSRYL0scf9M4eqJAiOyLcH378wu', 'employee', 6, NULL, NULL, NULL, '2025-08-20 10:48:15'),
(11, 'dave@gmail.com', '$2y$10$LB3I38FbIAXTWW/m4rEME.r24fiDYaYv1rF73h/ja4K7jxJU/zLbW', 'employee', 8, NULL, NULL, NULL, '2025-08-20 11:03:06'),
(12, 'angle@gmail.com', '$2y$10$/uQQerOin0fxGhXZB9/bee7blFO6/eEmhT2DgjpMXoXr/Vfbvo.y6', 'employee', 13, NULL, NULL, NULL, '2025-08-20 11:19:48'),
(13, 'reyes@gmail.com', '$2y$10$ZcsP14vChRDUKY28WIuz2.yExYsYPhaLEFiN8H83Fqvx54OB78vfO', 'employee', 14, NULL, NULL, NULL, '2025-08-20 11:21:05'),
(14, 'maria@gmail.com', '$2y$10$KwOpkSbKzJzLKCluWpTgTuBNGH.oemYO8uQzc55ZtLYBUcrUg07A.', 'manager', 15, NULL, NULL, NULL, '2025-08-20 11:24:03'),
(15, 'carlo@gmail.com', '$2y$10$3WBnPrwZHUEJcFxHBoCe.OTmy2ACEHDYC6SCwbsEfPIj3IJbwDegm', 'manager', 16, NULL, NULL, NULL, '2025-08-20 11:25:06'),
(16, 'sofia@gmail.com', '$2y$10$vNSdOYl7Q4ECDXrVZuxcfuWo5yRYT1F1WhFRagEVwGPL9mx6HHGUe', 'employee', 18, NULL, NULL, NULL, '2025-08-20 11:27:21');

-- --------------------------------------------------------


--
-- Indexes for dumped tables
--

--
-- Indexes for table `tblattendance`
--
ALTER TABLE `tblattendance`
  ADD PRIMARY KEY (`attendance_id`),
  ADD UNIQUE KEY `uniq_attendance_employee_date` (`employee_id`,`attendance_date`);

--
-- Indexes for table `tblattendancereports`
--
ALTER TABLE `tblattendancereports`
  ADD PRIMARY KEY (`Report_ID`),
  ADD KEY `fk_ar_attendance` (`Attendance_ID`),
  ADD KEY `fk_ar_employee` (`Employee_ID`),
  ADD KEY `fk_ar_generated_by` (`Generated_By`);

--
-- Indexes for table `tblattendance_daily_summary`
--
ALTER TABLE `tblattendance_daily_summary`
  ADD PRIMARY KEY (`summary_id`),
  ADD UNIQUE KEY `uniq_summary_date` (`summary_date`);

--
-- Indexes for table `tblattendance_employee_daily`
--
ALTER TABLE `tblattendance_employee_daily`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_emp_date` (`employee_id`,`attendance_date`),
  ADD KEY `fk_emp_daily_employee` (`employee_id`);

--
-- Indexes for table `tblaudit_logs`
--
ALTER TABLE `tblaudit_logs`
  ADD PRIMARY KEY (`log_id`),
  ADD KEY `fk_audit_user` (`user_id`);

--
-- Indexes for table `tbldeductionreports`
--
ALTER TABLE `tbldeductionreports`
  ADD PRIMARY KEY (`Report_ID`),
  ADD KEY `fk_dr_deduction` (`Deduction_ID`),
  ADD KEY `fk_dr_employee` (`Employee_ID`),
  ADD KEY `fk_dr_payroll` (`Payroll_ID`),
  ADD KEY `fk_dr_generated_by2` (`Generated_By`);

--
-- Indexes for table `tbldeductions`
--
ALTER TABLE `tbldeductions`
  ADD PRIMARY KEY (`deduct_id`),
  ADD UNIQUE KEY `uniq_deductions_name` (`name`);

--
-- Indexes for table `tbldepartmentreports`
--
ALTER TABLE `tbldepartmentreports`
  ADD PRIMARY KEY (`Report_ID`),
  ADD KEY `fk_dr_department` (`Department_ID`),
  ADD KEY `fk_dr_generated_by` (`Generated_By`);

--
-- Indexes for table `tbldepartments`
--
ALTER TABLE `tbldepartments`
  ADD PRIMARY KEY (`dept_id`),
  ADD UNIQUE KEY `uniq_departments_name` (`dept_name`);

--
-- Indexes for table `tbldepartment_positions`
--
ALTER TABLE `tbldepartment_positions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uniq_dept_position` (`dept_id`,`position_name`);

--
-- Indexes for table `tblemployeereports`
--
ALTER TABLE `tblemployeereports`
  ADD PRIMARY KEY (`Report_ID`),
  ADD KEY `fk_er_employee` (`Employee_ID`),
  ADD KEY `fk_er_department` (`Department_ID`),
  ADD KEY `fk_er_generated_by` (`Generated_By`);

--
-- Indexes for table `tblemployees`
--
ALTER TABLE `tblemployees`
  ADD PRIMARY KEY (`employee_id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Indexes for table `tblemployee_deductions`
--
ALTER TABLE `tblemployee_deductions`
  ADD PRIMARY KEY (`emp_deduct_id`),
  ADD KEY `fk_empded_employee` (`employee_id`),
  ADD KEY `fk_empded_deduct` (`deduct_id`);

--
-- Indexes for table `tblemployee_financial_details`
--
ALTER TABLE `tblemployee_financial_details`
  ADD PRIMARY KEY (`fin_id`),
  ADD UNIQUE KEY `uniq_employee_fin` (`employee_id`);

--
-- Indexes for table `tblemployee_workday_summary`
--
ALTER TABLE `tblemployee_workday_summary`
  ADD PRIMARY KEY (`summary_id`),
  ADD UNIQUE KEY `uniq_emp_period_summary` (`employee_id`,`period_id`),
  ADD KEY `idx_ews_period` (`period_id`);

--
-- Indexes for table `tblholidays`
--
ALTER TABLE `tblholidays`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `tblleaves`
--
ALTER TABLE `tblleaves`
  ADD PRIMARY KEY (`leave_id`),
  ADD KEY `fk_leaves_employee` (`employee_id`),
  ADD KEY `fk_leaves_approved_by` (`approved_by`),
  ADD KEY `fk_leaves_rejected_by` (`rejected_by`);

--
-- Indexes for table `tblleave_archive`
--
ALTER TABLE `tblleave_archive`
  ADD PRIMARY KEY (`archive_id`),
  ADD KEY `idx_larch_leave` (`leave_id`),
  ADD KEY `idx_larch_employee` (`employee_id`),
  ADD KEY `idx_larch_status` (`status`),
  ADD KEY `idx_larch_archived_at` (`archived_at`),
  ADD KEY `fk_larch_approved_by` (`approved_by`),
  ADD KEY `fk_larch_rejected_by` (`rejected_by`),
  ADD KEY `fk_larch_archived_by` (`archived_by`);

--
-- Indexes for table `tblleave_cancellations`
--
ALTER TABLE `tblleave_cancellations`
  ADD PRIMARY KEY (`cancel_id`),
  ADD KEY `fk_lc_leave` (`leave_id`),
  ADD KEY `fk_lc_employee` (`employee_id`),
  ADD KEY `fk_lc_cancelled_by` (`cancelled_by_user_id`);

--
-- Indexes for table `tblleave_types`
--
ALTER TABLE `tblleave_types`
  ADD PRIMARY KEY (`type_id`),
  ADD UNIQUE KEY `uniq_leave_types_name` (`name`),
  ADD KEY `idx_leave_types_active` (`is_active`),
  ADD KEY `idx_leave_types_sort` (`sort_order`);

--
-- Indexes for table `tblnotifications`
--
ALTER TABLE `tblnotifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_notifications_employee` (`employee_id`),
  ADD KEY `fk_notifications_actor` (`actor_user_id`);

--
-- Indexes for table `tblovertime_requests`
--
ALTER TABLE `tblovertime_requests`
  ADD PRIMARY KEY (`ot_id`),
  ADD KEY `fk_ot_employee` (`employee_id`),
  ADD KEY `fk_ot_approved_by` (`approved_by`),
  ADD KEY `fk_ot_rejected_by` (`rejected_by`),
  ADD KEY `idx_ot_employee_date` (`employee_id`,`work_date`),
  ADD KEY `idx_ot_status` (`status`);

--
-- Indexes for table `tblpayroll`
--
ALTER TABLE `tblpayroll`
  ADD PRIMARY KEY (`payroll_id`),
  ADD KEY `fk_payroll_paid_by` (`paid_by`),
  ADD KEY `idx_payroll_status` (`status`),
  ADD KEY `idx_payroll_period` (`employee_id`,`payroll_period_start`,`payroll_period_end`);

--
-- Indexes for table `tblpayrollreports`
--
ALTER TABLE `tblpayrollreports`
  ADD PRIMARY KEY (`Report_ID`),
  ADD KEY `fk_pr_payroll` (`Payroll_ID`),
  ADD KEY `fk_pr_employee` (`Employee_ID`),
  ADD KEY `fk_pr_generated_by` (`Generated_By`);

--
-- Indexes for table `tblpayroll_archive`
--
ALTER TABLE `tblpayroll_archive`
  ADD PRIMARY KEY (`archive_id`),
  ADD KEY `idx_parch_payroll` (`payroll_id`),
  ADD KEY `idx_parch_employee` (`employee_id`),
  ADD KEY `idx_parch_archived_at` (`archived_at`),
  ADD KEY `fk_parch_archived_by` (`archived_by`);

--
-- Indexes for table `tblpayroll_period`
--
ALTER TABLE `tblpayroll_period`
  ADD PRIMARY KEY (`period_id`),
  ADD UNIQUE KEY `uniq_payroll_period` (`period_start`,`period_end`);

--
-- Indexes for table `tblpayroll_slip_downloads`
--
ALTER TABLE `tblpayroll_slip_downloads`
  ADD PRIMARY KEY (`download_id`),
  ADD KEY `fk_psd_user` (`user_id`),
  ADD KEY `idx_psd_payroll` (`payroll_id`),
  ADD KEY `idx_psd_downloaded_at` (`downloaded_at`);

--
-- Indexes for table `tblpayslip_history`
--
ALTER TABLE `tblpayslip_history`
  ADD PRIMARY KEY (`history_id`),
  ADD UNIQUE KEY `uniq_payslip_per_payroll_employee` (`payroll_id`,`employee_id`),
  ADD KEY `idx_ph_payroll` (`payroll_id`),
  ADD KEY `idx_ph_employee` (`employee_id`),
  ADD KEY `idx_ph_generated_at` (`generated_at`),
  ADD KEY `fk_ph_generated_by` (`generated_by`);

--
-- Indexes for table `tblsystem_settings`
--
ALTER TABLE `tblsystem_settings`
  ADD PRIMARY KEY (`setting_key`);

--
-- Indexes for table `tblundertime_requests`
--
ALTER TABLE `tblundertime_requests`
  ADD PRIMARY KEY (`ut_id`),
  ADD KEY `fk_ut_employee` (`employee_id`),
  ADD KEY `fk_ut_approved_by` (`approved_by`),
  ADD KEY `fk_ut_rejected_by` (`rejected_by`),
  ADD KEY `idx_ut_employee_date` (`employee_id`,`work_date`),
  ADD KEY `idx_ut_status` (`status`);

--
-- Indexes for table `tblpayroll_by_batch`
--
ALTER TABLE `tblpayroll_by_batch`
  ADD PRIMARY KEY (`batch_id`),
  ADD KEY `fk_pbb_generated_by` (`generated_by`);

--
-- Indexes for table `tblpayroll_batch_employees`
--
ALTER TABLE `tblpayroll_batch_employees`
  ADD PRIMARY KEY (`batch_emp_id`),
  ADD KEY `fk_pbe_batch` (`batch_id`),
  ADD KEY `fk_pbe_employee` (`employee_id`);

--
-- Indexes for table `tblusers`
--
ALTER TABLE `tblusers`
  ADD PRIMARY KEY (`user_id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD KEY `fk_users_employee` (`employee_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `tblattendance`
--
ALTER TABLE `tblattendance`
  MODIFY `attendance_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblattendancereports`
--
ALTER TABLE `tblattendancereports`
  MODIFY `Report_ID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblattendance_daily_summary`
--
ALTER TABLE `tblattendance_daily_summary`
  MODIFY `summary_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblattendance_employee_daily`
--
ALTER TABLE `tblattendance_employee_daily`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblaudit_logs`
--
ALTER TABLE `tblaudit_logs`
  MODIFY `log_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=22;

--
-- AUTO_INCREMENT for table `tbldeductionreports`
--
ALTER TABLE `tbldeductionreports`
  MODIFY `Report_ID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tbldeductions`
--
ALTER TABLE `tbldeductions`
  MODIFY `deduct_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `tbldepartmentreports`
--
ALTER TABLE `tbldepartmentreports`
  MODIFY `Report_ID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tbldepartments`
--
ALTER TABLE `tbldepartments`
  MODIFY `dept_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `tbldepartment_positions`
--
ALTER TABLE `tbldepartment_positions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=26;

--
-- AUTO_INCREMENT for table `tblemployeereports`
--
ALTER TABLE `tblemployeereports`
  MODIFY `Report_ID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblemployees`
--
ALTER TABLE `tblemployees`
  MODIFY `employee_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT for table `tblemployee_deductions`
--
ALTER TABLE `tblemployee_deductions`
  MODIFY `emp_deduct_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblemployee_financial_details`
--
ALTER TABLE `tblemployee_financial_details`
  MODIFY `fin_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- AUTO_INCREMENT for table `tblemployee_workday_summary`
--
ALTER TABLE `tblemployee_workday_summary`
  MODIFY `summary_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblholidays`
--
ALTER TABLE `tblholidays`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblleaves`
--
ALTER TABLE `tblleaves`
  MODIFY `leave_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `tblleave_archive`
--
ALTER TABLE `tblleave_archive`
  MODIFY `archive_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblleave_cancellations`
--
ALTER TABLE `tblleave_cancellations`
  MODIFY `cancel_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblleave_types`
--
ALTER TABLE `tblleave_types`
  MODIFY `type_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `tblnotifications`
--
ALTER TABLE `tblnotifications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `tblovertime_requests`
--
ALTER TABLE `tblovertime_requests`
  MODIFY `ot_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblpayroll`
--
ALTER TABLE `tblpayroll`
  MODIFY `payroll_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblpayrollreports`
--
ALTER TABLE `tblpayrollreports`
  MODIFY `Report_ID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblpayroll_archive`
--
ALTER TABLE `tblpayroll_archive`
  MODIFY `archive_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblpayroll_period`
--
ALTER TABLE `tblpayroll_period`
  MODIFY `period_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `tblpayroll_by_batch`
--
ALTER TABLE `tblpayroll_by_batch`
  MODIFY `batch_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblpayroll_batch_employees`
--
ALTER TABLE `tblpayroll_batch_employees`
  MODIFY `batch_emp_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblpayroll_slip_downloads`
--
ALTER TABLE `tblpayroll_slip_downloads`
  MODIFY `download_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblpayslip_history`
--
ALTER TABLE `tblpayslip_history`
  MODIFY `history_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblundertime_requests`
--
ALTER TABLE `tblundertime_requests`
  MODIFY `ut_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `tblusers`
--
ALTER TABLE `tblusers`
  MODIFY `user_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `tblattendance`
--
ALTER TABLE `tblattendance`
  ADD CONSTRAINT `fk_att_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblattendancereports`
--
ALTER TABLE `tblattendancereports`
  ADD CONSTRAINT `fk_ar_attendance` FOREIGN KEY (`Attendance_ID`) REFERENCES `tblattendance` (`attendance_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ar_employee` FOREIGN KEY (`Employee_ID`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ar_generated_by` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;


--
-- Constraints for table `tblattendance_employee_daily`
--
ALTER TABLE `tblattendance_employee_daily`
  ADD CONSTRAINT `fk_emp_daily_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblaudit_logs`
--
ALTER TABLE `tblaudit_logs`
  ADD CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tbldeductionreports`
--
ALTER TABLE `tbldeductionreports`
  ADD CONSTRAINT `fk_dr_deduction` FOREIGN KEY (`Deduction_ID`) REFERENCES `tbldeductions` (`deduct_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_dr_employee` FOREIGN KEY (`Employee_ID`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_dr_generated_by2` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_dr_payroll` FOREIGN KEY (`Payroll_ID`) REFERENCES `tblpayroll` (`payroll_id`) ON DELETE SET NULL;

--
-- Constraints for table `tbldepartmentreports`
--
ALTER TABLE `tbldepartmentreports`
  ADD CONSTRAINT `fk_dr_department` FOREIGN KEY (`Department_ID`) REFERENCES `tbldepartments` (`dept_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_dr_generated_by` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tbldepartment_positions`
--
ALTER TABLE `tbldepartment_positions`
  ADD CONSTRAINT `fk_dp_department` FOREIGN KEY (`dept_id`) REFERENCES `tbldepartments` (`dept_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblemployeereports`
--
ALTER TABLE `tblemployeereports`
  ADD CONSTRAINT `fk_er_department` FOREIGN KEY (`Department_ID`) REFERENCES `tbldepartments` (`dept_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_er_employee` FOREIGN KEY (`Employee_ID`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_er_generated_by` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tblemployee_deductions`
--
ALTER TABLE `tblemployee_deductions`
  ADD CONSTRAINT `fk_empded_deduct` FOREIGN KEY (`deduct_id`) REFERENCES `tbldeductions` (`deduct_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_empded_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblemployee_financial_details`
--
ALTER TABLE `tblemployee_financial_details`
  ADD CONSTRAINT `fk_fin_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblemployee_workday_summary`
--
ALTER TABLE `tblemployee_workday_summary`
  ADD CONSTRAINT `fk_ews_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ews_period` FOREIGN KEY (`period_id`) REFERENCES `tblpayroll_period` (`period_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblleaves`
--
ALTER TABLE `tblleaves`
  ADD CONSTRAINT `fk_leaves_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_leaves_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_leaves_rejected_by` FOREIGN KEY (`rejected_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tblleave_archive`
--
ALTER TABLE `tblleave_archive`
  ADD CONSTRAINT `fk_larch_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_larch_archived_by` FOREIGN KEY (`archived_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_larch_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_larch_leave` FOREIGN KEY (`leave_id`) REFERENCES `tblleaves` (`leave_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_larch_rejected_by` FOREIGN KEY (`rejected_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tblleave_cancellations`
--
ALTER TABLE `tblleave_cancellations`
  ADD CONSTRAINT `fk_lc_cancelled_by` FOREIGN KEY (`cancelled_by_user_id`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_lc_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_lc_leave` FOREIGN KEY (`leave_id`) REFERENCES `tblleaves` (`leave_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblnotifications`
--
ALTER TABLE `tblnotifications`
  ADD CONSTRAINT `fk_notifications_actor` FOREIGN KEY (`actor_user_id`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_notifications_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblovertime_requests`
--
ALTER TABLE `tblovertime_requests`
  ADD CONSTRAINT `fk_ot_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_ot_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ot_rejected_by` FOREIGN KEY (`rejected_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tblpayroll`
--
ALTER TABLE `tblpayroll`
  ADD CONSTRAINT `fk_payroll_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_payroll_paid_by` FOREIGN KEY (`paid_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tblpayrollreports`
--
ALTER TABLE `tblpayrollreports`
  ADD CONSTRAINT `fk_pr_employee` FOREIGN KEY (`Employee_ID`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_pr_generated_by` FOREIGN KEY (`Generated_By`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_pr_payroll` FOREIGN KEY (`Payroll_ID`) REFERENCES `tblpayroll` (`payroll_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblpayroll_archive`
--
ALTER TABLE `tblpayroll_archive`
  ADD CONSTRAINT `fk_parch_archived_by` FOREIGN KEY (`archived_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_parch_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_parch_payroll` FOREIGN KEY (`payroll_id`) REFERENCES `tblpayroll` (`payroll_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblpayroll_slip_downloads`
--
ALTER TABLE `tblpayroll_slip_downloads`
  ADD CONSTRAINT `fk_psd_payroll` FOREIGN KEY (`payroll_id`) REFERENCES `tblpayroll` (`payroll_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_psd_user` FOREIGN KEY (`user_id`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tblpayslip_history`
--
ALTER TABLE `tblpayslip_history`
  ADD CONSTRAINT `fk_ph_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ph_generated_by` FOREIGN KEY (`generated_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_ph_payroll` FOREIGN KEY (`payroll_id`) REFERENCES `tblpayroll` (`payroll_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblpayroll_by_batch`
--
ALTER TABLE `tblpayroll_by_batch`
  ADD CONSTRAINT `fk_pbb_generated_by` FOREIGN KEY (`generated_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tblpayroll_batch_employees`
--
ALTER TABLE `tblpayroll_batch_employees`
  ADD CONSTRAINT `fk_pbe_batch` FOREIGN KEY (`batch_id`) REFERENCES `tblpayroll_by_batch` (`batch_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_pbe_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `tblundertime_requests`
--
ALTER TABLE `tblundertime_requests`
  ADD CONSTRAINT `fk_ut_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_ut_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ut_rejected_by` FOREIGN KEY (`rejected_by`) REFERENCES `tblusers` (`user_id`) ON DELETE SET NULL;

--
-- Constraints for table `tblusers`
--
ALTER TABLE `tblusers`
  ADD CONSTRAINT `fk_users_employee` FOREIGN KEY (`employee_id`) REFERENCES `tblemployees` (`employee_id`) ON DELETE SET NULL;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
