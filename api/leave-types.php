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
    $operation = isset($_GET['operation']) ? $_GET['operation'] : 'list';
  } else if ($method === 'POST') {
    $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
    $json = isset($_POST['json']) ? $_POST['json'] : '';
  }

  try {
    switch ($operation) {
      case 'list':
        echo listLeaveTypes($conn);
        break;
      case 'listActive':
        echo listLeaveTypes($conn, true);
        break;
      case 'create':
        echo createLeaveType($conn, $json);
        break;
      case 'update':
        echo updateLeaveType($conn, $json);
        break;
      case 'delete':
        echo deleteLeaveType($conn, $json);
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
   * RETRIEVE LEAVE TYPES LIST
   * Fetches leave types with optional active filter
   * Ordered by sort order and name for consistency
   */
  function listLeaveTypes($conn, $onlyActive = false) {
    $sql = 'SELECT type_id AS id, name, description, is_active, sort_order, created_at FROM tblleave_types';
    if ($onlyActive) { $sql .= ' WHERE is_active = 1'; }
    $sql .= ' ORDER BY sort_order ASC, name ASC';
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    return json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
  }

  /**
   * CREATE NEW LEAVE TYPE
   * Adds leave type with unique name validation
   * Supports active status and sort ordering
   */
  function createLeaveType($conn, $json) {
    $data = json_decode($json, true);
    $name = isset($data['name']) ? trim($data['name']) : '';
    $description = isset($data['description']) ? trim($data['description']) : null;
    $is_active = isset($data['is_active']) ? (int)!!$data['is_active'] : 1;
    $sort_order = isset($data['sort_order']) ? (int)$data['sort_order'] : 0;
    if ($name === '') {
      http_response_code(422);
      return json_encode(['success' => 0, 'message' => 'Name is required']);
    }
    // Insert
    $sql = 'INSERT INTO tblleave_types(name, description, is_active, sort_order) VALUES(:name, :description, :is_active, :sort_order)';
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':name', $name);
    $stmt->bindParam(':description', $description);
    $stmt->bindParam(':is_active', $is_active, PDO::PARAM_INT);
    $stmt->bindParam(':sort_order', $sort_order, PDO::PARAM_INT);
    try {
      $stmt->execute();
    } catch (PDOException $e) {
      if ((int)$e->getCode() === 23000) {
        http_response_code(409);
        return json_encode(['success' => 0, 'message' => 'Leave type name already exists']);
      }
      throw $e;
    }

    $id = (int)$conn->lastInsertId();
    $row = getById($conn, $id);
    return json_encode(['success' => 1, 'data' => $row]);
  }

  /**
   * UPDATE EXISTING LEAVE TYPE
   * Modifies leave type with partial update support
   * Maintains name uniqueness constraints
   */
  function updateLeaveType($conn, $json) {
    $data = json_decode($json, true);
    $id = isset($data['id']) ? (int)$data['id'] : (isset($data['type_id']) ? (int)$data['type_id'] : 0);
    if ($id <= 0) { http_response_code(422); return json_encode(['success' => 0, 'message' => 'Invalid id']); }
    $name = isset($data['name']) ? trim($data['name']) : null;
    $description = array_key_exists('description', $data) ? trim((string)$data['description']) : null;
    $is_active = isset($data['is_active']) ? (int)!!$data['is_active'] : null;
    $sort_order = isset($data['sort_order']) ? (int)$data['sort_order'] : null;

    // Build dynamic SET clause
    $fields = [];
    if ($name !== null) { $fields['name'] = $name; }
    if ($description !== null) { $fields['description'] = $description; }
    if ($is_active !== null) { $fields['is_active'] = $is_active; }
    if ($sort_order !== null) { $fields['sort_order'] = $sort_order; }
    if (empty($fields)) { return json_encode(['success' => 0, 'message' => 'Nothing to update']); }

    $setParts = [];
    foreach ($fields as $k => $v) { $setParts[] = "$k = :$k"; }
    $sql = 'UPDATE tblleave_types SET ' . implode(', ', $setParts) . ' WHERE type_id = :id';
    $stmt = $conn->prepare($sql);
    foreach ($fields as $k => $v) {
      if ($k === 'is_active' || $k === 'sort_order') {
        $stmt->bindValue(":$k", (int)$v, PDO::PARAM_INT);
      } else {
        $stmt->bindValue(":$k", $v);
      }
    }
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);

    try {
      $stmt->execute();
    } catch (PDOException $e) {
      if ((int)$e->getCode() === 23000) {
        http_response_code(409);
        return json_encode(['success' => 0, 'message' => 'Leave type name already exists']);
      }
      throw $e;
    }

    $row = getById($conn, $id);
    return json_encode(['success' => 1, 'data' => $row]);
  }

  /**
   * DELETE LEAVE TYPE
   * Removes leave type from system
   * Used for leave type management cleanup
   */
  function deleteLeaveType($conn, $json) {
    $data = json_decode($json, true);
    $id = isset($data['id']) ? (int)$data['id'] : (isset($data['type_id']) ? (int)$data['type_id'] : 0);
    if ($id <= 0) { http_response_code(422); return json_encode(['success' => 0]); }

    $stmt = $conn->prepare('DELETE FROM tblleave_types WHERE type_id = :id');
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    return json_encode(['success' => 1]);
  }

  /**
   * HELPER: GET LEAVE TYPE BY ID
   * Internal function to fetch leave type details
   * Reused by create and update operations
   */
  function getById($conn, $id) {
    $stmt = $conn->prepare('SELECT type_id AS id, name, description, is_active, sort_order, created_at FROM tblleave_types WHERE type_id = :id');
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetch(PDO::FETCH_ASSOC);
  }
