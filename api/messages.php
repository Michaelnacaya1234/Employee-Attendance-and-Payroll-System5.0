<?php
  header('Content-Type: application/json');
  header('Access-Control-Allow-Origin: *');
  header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
  header('Access-Control-Allow-Headers: Content-Type');

  if (session_status() === PHP_SESSION_NONE) { session_start(); }
  if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { exit(0); }

  require_once __DIR__ . '/connection-pdo.php';

  $operation = isset($_REQUEST['operation']) ? $_REQUEST['operation'] : '';
  $json = isset($_POST['json']) ? $_POST['json'] : '';

  try {
    switch ($operation) {
      case 'unreadCount':
        echo unreadCount($conn);
        break;
      case 'getRecipients':
        echo getRecipients($conn);
        break;
      case 'getConversations':
        echo getConversations($conn);
        break;
      case 'getMessages':
        echo getMessages($conn);
        break;
      case 'sendMessage':
        echo sendMessage($conn, $json);
        break;
      case 'markAsRead':
        echo markAsRead($conn, $json);
        break;
      default:
        echo json_encode(['success' => 0, 'message' => 'Invalid operation']);
    }
  } catch (Exception $e) {
    echo json_encode(['success' => 0, 'message' => 'Server error', 'error' => $e->getMessage()]);
  }

  function requireAuth(){
    if (!isset($_SESSION['user_id']) || intval($_SESSION['user_id']) <= 0) {
      echo json_encode(['success' => 0, 'message' => 'Not authenticated']);
      exit;
    }
  }

  function currentUserId(){ return isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 0; }

  function getUserBrief($conn, $userId){
    $u = [ 'user_id' => (int)$userId, 'username' => null, 'role' => null, 'employee_id' => null, 'first_name' => null, 'last_name' => null, 'full_name' => null ];
    try {
      $stmt = $conn->prepare("SELECT u.user_id, u.username, u.role, u.employee_id, e.first_name, e.last_name FROM tblusers u LEFT JOIN tblemployees e ON e.employee_id = u.employee_id WHERE u.user_id = :id LIMIT 1");
      $stmt->bindParam(':id', $userId, PDO::PARAM_INT);
      $stmt->execute();
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      if ($row) {
        $u['username'] = $row['username'];
        $u['role'] = $row['role'];
        $u['employee_id'] = $row['employee_id'] ? (int)$row['employee_id'] : null;
        $u['first_name'] = $row['first_name'] ?: null;
        $u['last_name'] = $row['last_name'] ?: null;
        $u['full_name'] = trim(($row['first_name'] ?: '') . ' ' . ($row['last_name'] ?: '')) ?: $row['username'];
      }
    } catch (Exception $e) { /* ignore */ }
    return $u;
  }

  function unreadCount($conn){
    requireAuth();
    $uid = currentUserId();
    try {
      $stmt = $conn->prepare("SELECT COUNT(*) AS c FROM tblmessages WHERE receiver_id = :uid AND status = 'unread'");
      $stmt->bindParam(':uid', $uid, PDO::PARAM_INT);
      $stmt->execute();
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      $count = (int)($row ? $row['c'] : 0);
      return json_encode($count);
    } catch (Exception $e) {
      return json_encode(0);
    }
  }

  function getRecipients($conn){
    requireAuth();
    $role = isset($_GET['role']) ? strtolower(trim($_GET['role'])) : '';
    $q = isset($_GET['q']) ? trim($_GET['q']) : '';

    $allowed = ['admin','hr','manager','employee'];
    $params = [];
    $where = '1=1';
    if ($role !== '' && in_array($role, $allowed, true)) { $where .= ' AND u.role = :r'; $params[':r'] = $role; }
    if ($q !== '') { $where .= ' AND (u.username LIKE :q OR e.first_name LIKE :q OR e.last_name LIKE :q)'; $params[':q'] = '%' . $q . '%'; }

    try {
      $sql = "SELECT u.user_id, u.username, u.role, u.employee_id, e.first_name, e.last_name, e.email, e.department, e.position
              FROM tblusers u LEFT JOIN tblemployees e ON e.employee_id = u.employee_id WHERE $where ORDER BY e.last_name, e.first_name, u.username";
      $stmt = $conn->prepare($sql);
      foreach ($params as $k => $v) {
        if ($k === ':r') $stmt->bindParam($k, $params[$k]);
        else $stmt->bindValue($k, $v);
      }
      $stmt->execute();
      $list = [];
      while ($r = $stmt->fetch(PDO::FETCH_ASSOC)){
        $full = trim(($r['first_name'] ?: '') . ' ' . ($r['last_name'] ?: ''));
        $list[] = [
          'user_id' => (int)$r['user_id'],
          'username' => $r['username'],
          'role' => $r['role'],
          'employee_id' => $r['employee_id'] ? (int)$r['employee_id'] : null,
          'full_name' => $full !== '' ? $full : $r['username'],
          'email' => $r['email'] ?: null,
          'department' => $r['department'] ?: null,
          'position' => $r['position'] ?: null
        ];
      }
      return json_encode(['success' => 1, 'recipients' => $list]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Failed to load recipients']);
    }
  }

  function getConversations($conn){
    requireAuth();
    $uid = currentUserId();
    $roleFilter = isset($_GET['role']) ? strtolower(trim($_GET['role'])) : '';

    try {
      $stmt = $conn->prepare("SELECT CASE WHEN sender_id = :uid THEN receiver_id ELSE sender_id END AS peer_id,
                                      SUM(CASE WHEN receiver_id = :uid AND status = 'unread' THEN 1 ELSE 0 END) AS unread_count,
                                      MAX(created_at) AS last_at
                               FROM tblmessages
                               WHERE sender_id = :uid OR receiver_id = :uid
                               GROUP BY peer_id
                               ORDER BY last_at DESC");
      $stmt->bindParam(':uid', $uid, PDO::PARAM_INT);
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

      $items = [];
      foreach ($rows as $row){
        $peerId = (int)$row['peer_id'];
        if ($peerId <= 0) continue;
        $peer = getUserBrief($conn, $peerId);
        if ($roleFilter !== '' && $peer['role'] && strtolower($peer['role']) !== $roleFilter) { continue; }
        // Fetch last message
        $last = null;
        try {
          $q = $conn->prepare("SELECT message_id, sender_id, receiver_id, subject, message, status, created_at
                                FROM tblmessages
                                WHERE (sender_id = :u AND receiver_id = :p) OR (sender_id = :p AND receiver_id = :u)
                                ORDER BY created_at DESC, message_id DESC LIMIT 1");
          $q->bindParam(':u', $uid, PDO::PARAM_INT);
          $q->bindParam(':p', $peerId, PDO::PARAM_INT);
          $q->execute();
          $last = $q->fetch(PDO::FETCH_ASSOC);
        } catch (Exception $e2) { /* ignore */ }

        $items[] = [
          'peer' => $peer,
          'unread' => (int)($row['unread_count'] ?? 0),
          'last' => $last ? [
            'message_id' => (int)$last['message_id'],
            'sender_id' => (int)$last['sender_id'],
            'receiver_id' => (int)$last['receiver_id'],
            'subject' => $last['subject'],
            'message' => $last['message'],
            'status' => $last['status'],
            'created_at' => $last['created_at']
          ] : null,
          'last_at' => $row['last_at']
        ];
      }

      return json_encode(['success' => 1, 'conversations' => $items]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Failed to load conversations']);
    }
  }

  function getMessages($conn){
    requireAuth();
    $uid = currentUserId();
    $peer = isset($_GET['user_id']) ? (int)$_GET['user_id'] : 0;
    if ($peer <= 0) { return json_encode(['success' => 0, 'message' => 'Invalid user']); }

    try {
      // Fetch messages between users
      $stmt = $conn->prepare("SELECT message_id, sender_id, receiver_id, subject, message, status, created_at, updated_at
                              FROM tblmessages
                              WHERE (sender_id = :u AND receiver_id = :p) OR (sender_id = :p AND receiver_id = :u)
                              ORDER BY created_at ASC, message_id ASC");
      $stmt->bindParam(':u', $uid, PDO::PARAM_INT);
      $stmt->bindParam(':p', $peer, PDO::PARAM_INT);
      $stmt->execute();
      $msgs = [];
      while ($r = $stmt->fetch(PDO::FETCH_ASSOC)){
        $msgs[] = [
          'message_id' => (int)$r['message_id'],
          'sender_id' => (int)$r['sender_id'],
          'receiver_id' => (int)$r['receiver_id'],
          'subject' => $r['subject'],
          'message' => $r['message'],
          'status' => $r['status'],
          'created_at' => $r['created_at'],
          'updated_at' => $r['updated_at']
        ];
      }

      // Mark peer->me messages as read
      try {
        $upd = $conn->prepare("UPDATE tblmessages SET status = 'read' WHERE sender_id = :p AND receiver_id = :u AND status = 'unread'");
        $upd->bindParam(':p', $peer, PDO::PARAM_INT);
        $upd->bindParam(':u', $uid, PDO::PARAM_INT);
        $upd->execute();
      } catch (Exception $e2) { /* ignore */ }

      $peerInfo = getUserBrief($conn, $peer);
      return json_encode(['success' => 1, 'peer' => $peerInfo, 'messages' => $msgs]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Failed to load messages']);
    }
  }

  function sendMessage($conn, $json){
    requireAuth();
    $data = json_decode($json, true);
    if (!is_array($data)) { $data = $_POST; }

    $receiver = isset($data['receiver_id']) ? (int)$data['receiver_id'] : 0;
    $message = isset($data['message']) ? trim($data['message']) : '';
    $subject = isset($data['subject']) ? trim($data['subject']) : null;

    if ($receiver <= 0 || $message === '') {
      return json_encode(['success' => 0, 'message' => 'Missing receiver or message']);
    }

    $sender = currentUserId();

    // Validate receiver exists
    try {
      $chk = $conn->prepare('SELECT user_id FROM tblusers WHERE user_id = :id LIMIT 1');
      $chk->bindParam(':id', $receiver, PDO::PARAM_INT);
      $chk->execute();
      $exists = $chk->fetch(PDO::FETCH_ASSOC);
      if (!$exists) { return json_encode(['success' => 0, 'message' => 'Receiver not found']); }
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Receiver not found']);
    }

    try {
      $stmt = $conn->prepare("INSERT INTO tblmessages(sender_id, receiver_id, subject, message, status, created_at) VALUES(:s, :r, :subj, :msg, 'unread', NOW())");
      $stmt->bindParam(':s', $sender, PDO::PARAM_INT);
      $stmt->bindParam(':r', $receiver, PDO::PARAM_INT);
      if ($subject !== null && $subject !== '') { $stmt->bindParam(':subj', $subject); }
      else { $stmt->bindValue(':subj', null, PDO::PARAM_NULL); }
      $stmt->bindParam(':msg', $message);
      $stmt->execute();
      $id = (int)$conn->lastInsertId();
      return json_encode(['success' => 1, 'message_id' => $id]);
    } catch (Exception $e) {
      return json_encode(['success' => 0, 'message' => 'Failed to send message']);
    }
  }

  function markAsRead($conn, $json){
    requireAuth();
    $data = json_decode($json, true);
    $peer = isset($data['user_id']) ? (int)$data['user_id'] : 0;
    if ($peer <= 0) { return json_encode(['success' => 0, 'message' => 'Invalid user']); }
    $uid = currentUserId();
    try {
      $upd = $conn->prepare("UPDATE tblmessages SET status = 'read' WHERE sender_id = :p AND receiver_id = :u AND status = 'unread'");
      $upd->bindParam(':p', $peer, PDO::PARAM_INT);
      $upd->bindParam(':u', $uid, PDO::PARAM_INT);
      $upd->execute();
      return json_encode(['success' => 1]);
    } catch (Exception $e) {
      return json_encode(['success' => 0]);
    }
  }
?>
