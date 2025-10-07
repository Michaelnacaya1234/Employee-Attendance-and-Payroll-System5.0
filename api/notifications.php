<?php
  header('Content-Type: application/json');
  header('Access-Control-Allow-Origin: *');

  if (session_status() === PHP_SESSION_NONE) {
    session_start();
  }

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
    case 'getNotifications':
      echo getNotifications($conn);
      break;
    case 'markAsRead':
      echo markAsRead($conn, $json);
      break;
    case 'deleteNotification':
      echo deleteNotification($conn, $json);
      break;
    case 'markAllAsRead':
      echo markAllAsRead($conn);
      break;
    case 'sendNotification':
      echo sendNotification($conn, $json);
      break;
    case 'getTemplates':
      echo getNotificationTemplates($conn);
      break;
    case 'deleteTemplate':
      echo deleteNotificationTemplate($conn, $json);
      break;
    case 'getNotificationHistory':
      echo getNotificationHistory($conn);
      break;
    default:
      echo json_encode(['success' => 0, 'message' => 'Invalid operation']);
  }

  /**
   * RETRIEVE USER NOTIFICATIONS
   * Fetches notifications for logged-in employee
   * Returns latest 50 notifications ordered by creation date
   */
  function getNotifications($conn){
    if (!isset($_SESSION['user_id'])){
      return json_encode(['success' => 0, 'message' => 'Not authenticated']);
    }
    
    try {
      // Get employee_id and role from the logged-in user
      $stmt = $conn->prepare("SELECT employee_id, role FROM tblusers WHERE user_id = :user_id LIMIT 1");
      $stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
      $stmt->execute();
      $user = $stmt->fetch(PDO::FETCH_ASSOC);

      $notifications = [];
      if ($user && isset($user['role']) && strtolower($user['role']) === 'admin') {
        // Admins should only see notifications addressed to their own employee_id to avoid duplicates
        $allowedTypes = "('payroll_processed', 'payroll_batch_created', 'password_reset', 'password_changed', 'account_lockout', 'account_blocked')";
        if (!empty($user['employee_id'])) {
          $eid = intval($user['employee_id']);
          $q = $conn->prepare("SELECT * FROM tblnotifications WHERE employee_id = :employee_id AND type IN $allowedTypes ORDER BY created_at DESC LIMIT 50");
          $q->bindParam(':employee_id', $eid, PDO::PARAM_INT);
        } else {
          // Fallback when admin account has no employee mapping: return de-duplicated notifications by type+message
          $q = $conn->prepare("SELECT MIN(id) AS id, type, message, MAX(created_at) AS created_at, MIN(read_at) AS read_at FROM tblnotifications WHERE type IN $allowedTypes GROUP BY type, message ORDER BY MAX(created_at) DESC LIMIT 50");
        }
        $q->execute();
        $notifications = $q->fetchAll(PDO::FETCH_ASSOC);
      } else if ($user && !empty($user['employee_id'])) {
        // Standard: notifications targeted to this employee
        $employee_id = intval($user['employee_id']);
        $q = $conn->prepare("SELECT * FROM tblnotifications WHERE employee_id = :employee_id ORDER BY created_at DESC LIMIT 50");
        $q->bindParam(':employee_id', $employee_id, PDO::PARAM_INT);
        $q->execute();
        $notifications = $q->fetchAll(PDO::FETCH_ASSOC);
      } else {
        // No mapping and not admin - return empty list
        $notifications = [];
      }
      
      return json_encode([
        'success' => 1,
        'notifications' => $notifications,
        'tblnotifications' => $notifications
      ]);
      
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Database error: ' . $e->getMessage()]);
    }
  }

  /**
   * MARK NOTIFICATION AS READ
   * Updates notification read timestamp
   * Used for notification status management
   */
  function markAsRead($conn, $json){
    if (!isset($_SESSION['user_id'])){
      return json_encode(['success' => 0, 'message' => 'Not authenticated']);
    }
    
    $data = json_decode($json, true);
    if (!isset($data['notification_id'])) {
      return json_encode(['success' => 0, 'message' => 'Notification ID required']);
    }
    
    try {
      $stmt = $conn->prepare("UPDATE tblnotifications SET read_at = NOW() WHERE id = :id");
      $stmt->bindParam(':id', $data['notification_id'], PDO::PARAM_INT);
      $stmt->execute();
      
      return json_encode(['success' => 1]);
      
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Database error: ' . $e->getMessage()]);
    }
  }

  /**
   * MARK ALL NOTIFICATIONS AS READ
   * Bulk update of unread notifications for current user
   * Improves user experience for notification cleanup
   */
  function markAllAsRead($conn){
    if (!isset($_SESSION['user_id'])){
      return json_encode(['success' => 0, 'message' => 'Not authenticated']);
    }
    try {
      // Resolve current user's employee_id
      $stmt = $conn->prepare("SELECT employee_id FROM tblusers WHERE user_id = :user_id LIMIT 1");
      $stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
      $stmt->execute();
      $user = $stmt->fetch(PDO::FETCH_ASSOC);
      if (!$user || !$user['employee_id']) {
        return json_encode(['success' => 0, 'message' => 'No employee mapping found']);
      }
      $eid = (int)$user['employee_id'];
      $upd = $conn->prepare("UPDATE tblnotifications SET read_at = NOW() WHERE employee_id = :eid AND read_at IS NULL");
      $upd->bindParam(':eid', $eid, PDO::PARAM_INT);
      $upd->execute();
      return json_encode(['success' => 1]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Database error: ' . $e->getMessage()]);
    }
  }

  /**
   * DELETE SINGLE NOTIFICATION
   * Permanently removes notification from system
   * Used for notification management and cleanup
   */
  function deleteNotification($conn, $json){
    if (!isset($_SESSION['user_id'])){
      return json_encode(['success' => 0, 'message' => 'Not authenticated']);
    }
    
    $data = json_decode($json, true);
    if (!isset($data['notification_id'])) {
      return json_encode(['success' => 0, 'message' => 'Notification ID required']);
    }
    
    try {
      $stmt = $conn->prepare("DELETE FROM tblnotifications WHERE id = :id");
      $stmt->bindParam(':id', $data['notification_id'], PDO::PARAM_INT);
      $stmt->execute();
      
      return json_encode(['success' => 1]);
      
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Database error: ' . $e->getMessage()]);
    }
  }

  /**
   * SEND NEW NOTIFICATION
   * Creates and sends notifications based on admin settings
   * Supports multiple recipient types and delivery methods
   */
  function sendNotification($conn, $json) {
    if (!isset($_SESSION['user_id'])) {
      return json_encode(['success' => 0, 'message' => 'Not authenticated']);
    }
    
    // Check if user has admin role
    $stmt = $conn->prepare("SELECT role FROM tblusers WHERE user_id = :user_id");
    $stmt->bindParam(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user || !in_array($user['role'], ['admin', 'hr'])) {
      return json_encode(['success' => 0, 'message' => 'Insufficient permissions']);
    }
    
    $data = json_decode($json, true);
    $required = ['type', 'recipients', 'subject', 'message'];
    
    foreach ($required as $field) {
      if (!isset($data[$field]) || trim($data[$field]) === '') {
        return json_encode(['success' => 0, 'message' => "Field '$field' is required"]);
      }
    }
    
    try {
      // Get recipient employee IDs based on type
      $recipientIds = getRecipientEmployeeIds($conn, $data['recipients']);
      
      if (empty($recipientIds)) {
        return json_encode(['success' => 0, 'message' => 'No valid recipients found']);
      }
      
      $sentCount = 0;
      $priority = $data['priority'] ?? 'normal';
      $deliveryMethod = $data['delivery_method'] ?? 'in_app';
      $sendImmediately = $data['send_immediately'] ?? true;
      $saveAsTemplate = $data['save_as_template'] ?? false;
      
      // Save as template if requested
      if ($saveAsTemplate) {
        try { saveNotificationTemplate($conn, $data, intval($_SESSION['user_id'])); } catch (Exception $e) {}
      }
      
      // Create notifications for each recipient
      foreach ($recipientIds as $employeeId) {
        $stmt = $conn->prepare("
          INSERT INTO tblnotifications (employee_id, type, message, created_at) 
          VALUES (:employee_id, :type, :message, NOW())
        ");
        
        $stmt->bindParam(':employee_id', $employeeId, PDO::PARAM_INT);
        $stmt->bindParam(':type', $data['type'], PDO::PARAM_STR);
        // Combine subject and message for now
        $fullMessage = $data['subject'] . "\n\n" . $data['message'];
        $stmt->bindParam(':message', $fullMessage, PDO::PARAM_STR);
        
        if ($stmt->execute()) {
          $sentCount++;
        }
      }
      
      // Log the notification send action (disabled until DB update)
      // logNotificationAction($conn, $_SESSION['user_id'], 'send_notification', [
      //   'type' => $data['type'],
      //   'recipients' => $data['recipients'],
      //   'subject' => $data['subject'],
      //   'sent_count' => $sentCount
      // ]);
      
      return json_encode([
        'success' => 1, 
        'message' => "Notification sent to $sentCount recipients",
        'sent_count' => $sentCount,
        'debug' => [
          'recipient_ids' => $recipientIds,
          'type' => $data['type'],
          'recipients' => $data['recipients']
        ]
      ]);
      
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Database error: ' . $e->getMessage()]);
    }
  }
  
  /**
   * GET RECIPIENT EMPLOYEE IDs
   * Resolves recipient types to actual employee IDs
   */
  function getRecipientEmployeeIds($conn, $recipients) {
    $ids = [];
    
    try {
      switch (strtolower($recipients)) {
        case 'all':
          $stmt = $conn->prepare("SELECT employee_id FROM tblusers WHERE employee_id IS NOT NULL AND employee_id > 0");
          $stmt->execute();
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          foreach ($results as $row) {
            $ids[] = intval($row['employee_id']);
          }
          break;
          
        case 'admin':
          $stmt = $conn->prepare("SELECT employee_id FROM tblusers WHERE role = 'admin' AND employee_id IS NOT NULL AND employee_id > 0");
          $stmt->execute();
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          foreach ($results as $row) {
            $ids[] = intval($row['employee_id']);
          }
          break;
          
        case 'hr':
          $stmt = $conn->prepare("SELECT employee_id FROM tblusers WHERE role = 'hr' AND employee_id IS NOT NULL AND employee_id > 0");
          $stmt->execute();
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          foreach ($results as $row) {
            $ids[] = intval($row['employee_id']);
          }
          break;
          
        case 'manager':
          $stmt = $conn->prepare("SELECT employee_id FROM tblusers WHERE role = 'manager' AND employee_id IS NOT NULL AND employee_id > 0");
          $stmt->execute();
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          foreach ($results as $row) {
            $ids[] = intval($row['employee_id']);
          }
          break;
          
        case 'employee':
          $stmt = $conn->prepare("SELECT employee_id FROM tblusers WHERE role = 'employee' AND employee_id IS NOT NULL AND employee_id > 0");
          $stmt->execute();
          $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
          foreach ($results as $row) {
            $ids[] = intval($row['employee_id']);
          }
          break;
          
        default:
          // Handle comma-separated specific employee IDs
          $specificIds = array_map('trim', explode(',', $recipients));
          foreach ($specificIds as $id) {
            if (is_numeric($id) && intval($id) > 0) {
              // Verify the employee ID exists
              $stmt = $conn->prepare("SELECT employee_id FROM tblusers WHERE employee_id = :id");
              $stmt->bindParam(':id', $id, PDO::PARAM_INT);
              $stmt->execute();
              if ($stmt->fetch()) {
                $ids[] = intval($id);
              }
            }
          }
          break;
      }
    } catch (Exception $e) {
      error_log("Error getting recipient IDs: " . $e->getMessage());
    }
    
    return array_unique($ids);
  }
  
  /**
   * SAVE NOTIFICATION TEMPLATE
   * Stores notification as reusable template
   */
  function saveNotificationTemplate($conn, $data, $userId) {
    try {
      $name = isset($data['name']) && trim($data['name']) !== ''
        ? trim($data['name'])
        : (isset($data['subject']) && trim($data['subject']) !== ''
            ? trim($data['subject'])
            : ((isset($data['type']) ? ucfirst(trim($data['type'])) : 'Notification') . ' Template'));
      $type = isset($data['type']) ? trim($data['type']) : 'general';
      $recipients = isset($data['recipients']) ? trim($data['recipients']) : 'all';
      $subject = isset($data['subject']) ? trim($data['subject']) : '';
      $message = isset($data['message']) ? trim($data['message']) : '';
      $priority = isset($data['priority']) ? trim($data['priority']) : 'normal';
      $delivery = isset($data['delivery_method']) ? trim($data['delivery_method']) : 'in_app';
      if ($subject === '' || $message === '') { return false; }

      $stmt = $conn->prepare("INSERT INTO tblnotification_templates (name, type, recipients, subject, message, priority, delivery_method, created_by) VALUES (:name, :type, :recipients, :subject, :message, :priority, :delivery_method, :created_by)");
      $stmt->bindParam(':name', $name);
      $stmt->bindParam(':type', $type);
      $stmt->bindParam(':recipients', $recipients);
      $stmt->bindParam(':subject', $subject);
      $stmt->bindParam(':message', $message);
      $stmt->bindParam(':priority', $priority);
      $stmt->bindParam(':delivery_method', $delivery);
      $stmt->bindParam(':created_by', $userId, PDO::PARAM_INT);
      return $stmt->execute();
    } catch (Exception $e) {
      error_log('saveNotificationTemplate error: ' . $e->getMessage());
      return false;
    }
  }
  
  /**
   * GET NOTIFICATION TEMPLATES
   * Retrieves saved notification templates
   */
  function getNotificationTemplates($conn) {
    if (!isset($_SESSION['user_id'])) {
      return json_encode(['success' => 0, 'message' => 'Not authenticated']);
    }
    try {
      $stmt = $conn->prepare("SELECT id, name, type, recipients, subject, message, priority, delivery_method, created_by, created_at, updated_at FROM tblnotification_templates ORDER BY created_at DESC");
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
      return json_encode($rows);
    } catch (Exception $e) {
      return json_encode([]);
    }
  }
  
  /**
   * DELETE NOTIFICATION TEMPLATE
   * Removes saved notification template by ID
   */
  function deleteNotificationTemplate($conn, $json) {
    if (!isset($_SESSION['user_id'])) {
      return json_encode(['success' => 0, 'message' => 'Not authenticated']);
    }

    // Only admins and HR can delete templates
    try {
      $roleStmt = $conn->prepare("SELECT role FROM tblusers WHERE user_id = :uid");
      $roleStmt->bindParam(':uid', $_SESSION['user_id'], PDO::PARAM_INT);
      $roleStmt->execute();
      $user = $roleStmt->fetch(PDO::FETCH_ASSOC);
      if (!$user || !in_array($user['role'], ['admin','hr'])) {
        return json_encode(['success' => 0, 'message' => 'Insufficient permissions']);
      }
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Database error: ' . $e->getMessage()]);
    }

    $data = json_decode($json, true);
    $templateId = isset($data['template_id']) ? intval($data['template_id']) : 0;
    if ($templateId <= 0) {
      return json_encode(['success' => 0, 'message' => 'Template ID required']);
    }

    try {
      $del = $conn->prepare("DELETE FROM tblnotification_templates WHERE id = :id");
      $del->bindParam(':id', $templateId, PDO::PARAM_INT);
      $del->execute();
      return json_encode(['success' => 1]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Database error: ' . $e->getMessage()]);
    }
  }
  
  /**
   * GET NOTIFICATION HISTORY
   * Retrieves sent notification history (temporarily simplified)
   */
  function getNotificationHistory($conn) {
    if (!isset($_SESSION['user_id'])) {
      return json_encode(['success' => 0, 'message' => 'Not authenticated']);
    }
    
    $filter = isset($_GET['filter']) ? $_GET['filter'] : null;
    
    try {
      // Base query for existing table structure
      $sql = "
        SELECT DISTINCT
          n.id,
          n.type,
          n.message,
          n.created_at,
          n.employee_id,
          e.FirstName, 
          e.LastName,
          COUNT(*) OVER (PARTITION BY n.type, LEFT(n.message, 50), DATE(n.created_at)) as recipient_count
        FROM tblnotifications n
        LEFT JOIN tblemployees e ON n.employee_id = e.EmployeeID
      ";
      
      $params = [];
      if ($filter && $filter !== 'all') {
        $sql .= " WHERE n.type = :filter";
        $params[':filter'] = $filter;
      }
      
      $sql .= " ORDER BY n.created_at DESC LIMIT 50";
      
      $stmt = $conn->prepare($sql);
      foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
      }
      $stmt->execute();
      
      $history = $stmt->fetchAll(PDO::FETCH_ASSOC);
      
      // Process the results to group similar notifications
      $processedHistory = [];
      $seenNotifications = [];
      
      foreach ($history as $item) {
        // Extract subject from message if it contains subject + message format
        $messageParts = explode("\n\n", $item['message'], 2);
        $subject = count($messageParts) > 1 ? $messageParts[0] : 'Notification';
        $actualMessage = count($messageParts) > 1 ? $messageParts[1] : $item['message'];
        
        // Create a unique key for grouping
        $groupKey = $item['type'] . '|' . substr($subject, 0, 50) . '|' . date('Y-m-d', strtotime($item['created_at']));
        
        if (!isset($seenNotifications[$groupKey])) {
          $processedHistory[] = [
            'id' => $item['id'],
            'subject' => $subject,
            'type' => $item['type'],
            'message' => $actualMessage,
            'recipients' => getRecipientsDisplayForHistory($item['recipient_count']),
            'status' => 'sent',
            'sent_at' => $item['created_at'],
            'created_at' => $item['created_at'],
            'recipient_count' => $item['recipient_count']
          ];
          $seenNotifications[$groupKey] = true;
        }
      }
      
      return json_encode($processedHistory);
      
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Database error: ' . $e->getMessage()]);
    }
  }
  
  /**
   * Get display text for recipients count
   */
  function getRecipientsDisplayForHistory($count) {
    if ($count == 1) {
      return '1 recipient';
    } else {
      return $count . ' recipients';
    }
  }
  
  /**
   * LOG NOTIFICATION ACTION
   * Records notification actions for audit purposes (temporarily disabled)
   */
  function logNotificationAction($conn, $userId, $action, $details) {
    // Temporarily disabled until audit table is created
    return true;
  }
?>
