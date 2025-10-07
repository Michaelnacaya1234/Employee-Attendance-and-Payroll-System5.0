<?php
// Email Configuration for Password Reset
// Update these values with your Gmail credentials

// Gmail SMTP Settings
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'nacayamjay@gmail.com'); // Your Gmail address
define('SMTP_PASSWORD', 'bixm mswc pyrl mnsm'); // Your Gmail app password
define('SMTP_FROM_EMAIL', 'nacayamjay@gmail.com'); // Your Gmail address
define('SMTP_FROM_NAME', 'Attendance System'); // Company/System name

// Email Settings
define('EMAIL_SUBJECT', 'Password Reset Code');
define('CODE_EXPIRY_MINUTES', 15);

// Security Settings
define('MAX_RESET_ATTEMPTS', 3);
define('RATE_LIMIT_HOURS', 1);
?>
