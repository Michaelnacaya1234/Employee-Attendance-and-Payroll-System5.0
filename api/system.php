<?php
  header('Content-Type: application/json');
  header('Access-Control-Allow-Origin: *');
  if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    exit(0);
  }

  if (session_status() === PHP_SESSION_NONE) { session_start(); }

  require_once __DIR__ . '/connection-pdo.php';

  $method = $_SERVER['REQUEST_METHOD'];
  $operation = '';
  $json = '';
  if ($method === 'GET') {
    $operation = isset($_GET['operation']) ? $_GET['operation'] : '';
  } else if ($method === 'POST') {
    $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
    $json = isset($_POST['json']) ? $_POST['json'] : '';
    if ($json === '') {
      // Fallback to raw JSON body if provided
      $raw = file_get_contents('php://input');
      if (!empty($raw)) { $json = $raw; }
    }
  }

  try {
    switch ($operation) {
      case 'getSystemSettings':
        echo getSystemSettings($conn);
        break;
      case 'updateSystemSettings':
        echo updateSystemSettings($conn, $json);
        break;
      // Backwards-compatibility aliases
      case 'list':
        echo getSystemSettings($conn);
        break;
      case 'update':
        echo updateSystemSettings($conn, $json);
        break;
      default:
        http_response_code(400);
        echo json_encode(['success' => 0, 'message' => 'Invalid operation']);
    }
  } catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => 0, 'message' => 'Server error', 'error' => $e->getMessage()]);
  }

  /**
   * RETRIEVE ALL SYSTEM SETTINGS
   * Fetches configuration settings from database
   * Returns key-value pairs for system configuration
   */
  function getSystemSettings($conn) {
    $sql = 'SELECT setting_key, setting_value FROM tblsystem_settings';
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $out = [];
    foreach ($rows as $r) {
      $key = isset($r['setting_key']) ? $r['setting_key'] : '';
      $val = array_key_exists('setting_value', $r) ? $r['setting_value'] : null;
      if ($key !== '') { $out[$key] = $val; }
    }
    return json_encode($out);
  }

  /**
   * UPDATE SYSTEM SETTINGS
   * Modifies multiple system configuration values
   * Handles JSON encoding for complex values
   */
  function updateSystemSettings($conn, $json) {
    $data = json_decode($json, true);
    if (!is_array($data)) { http_response_code(422); return json_encode(['success' => 0, 'message' => 'Invalid payload']); }

    // Only allow scalar values to be stored; JSON-encode non-scalars
    $norm = [];
    foreach ($data as $k => $v) {
      if (!is_string($k) || $k === '') continue;
      if (is_scalar($v) || $v === null) { $norm[$k] = ($v === null ? '' : (string)$v); }
      else { $norm[$k] = json_encode($v); }
    }

    if (empty($norm)) { return json_encode(['success' => 0, 'message' => 'Nothing to update']); }

    $sql = 'INSERT INTO tblsystem_settings (setting_key, setting_value) VALUES (:k, :v)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)';
    $stmt = $conn->prepare($sql);

    $conn->beginTransaction();
    try {
      foreach ($norm as $k => $v) {
        $stmt->bindValue(':k', $k, PDO::PARAM_STR);
        $stmt->bindValue(':v', $v, PDO::PARAM_STR);
        $stmt->execute();
      }
      $conn->commit();
    } catch (Exception $e) {
      $conn->rollBack();
      http_response_code(500);
      return json_encode(['success' => 0, 'message' => 'Failed to update settings', 'error' => $e->getMessage()]);
    }

    return json_encode(['success' => 1]);
  }
