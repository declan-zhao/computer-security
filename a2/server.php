<?php

/**
 * This file contains the request arbitration code for the password safe server.
 * It should be unnecessary for students to modify this file.
 **/

// include the APIs that students should use
require("api.php");
// include the resources code that students should modify
require("resources.php");

// Define constants for use when function calls require flags
define("CREATE_ASSOC_ARRAYS", true);
define("STRICT_TYPES", true);
define("COOKIE_PATH", "");
define("COOKIE_DOMAIN", "");
define("NOT_SECURE", false);
define("HTTP_ONLY", true);

// The request method
$request_method = $_SERVER["REQUEST_METHOD"];
// This is one way to get the raw post body in PHP
$decoded_post_body = json_decode(file_get_contents('php://input'), CREATE_ASSOC_ARRAYS);
// Just get the names of GET params, not the values
$url_params = array_keys($_GET);
// Get a PDO database connection that  will throw exceptions on failures
$pdo = new PDO("sqlite:passwordsafe.db", NULL, NULL, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false));

// https://www.php.net/manual/en/language.types.object.php#114442
class stdObject
{
  public function __construct(array $arguments = array())
  {
    if (!empty($arguments)) {
      foreach ($arguments as $property => $argument) {
        $this->{$property} = $argument;
      }
    }
  }

  public function __call($method, $arguments)
  {
    $arguments = array_merge(array("stdObject" => $this), $arguments);

    if (isset($this->{$method}) && is_callable($this->{$method})) {
      return call_user_func_array($this->{$method}, $arguments);
    } else {
      throw new Exception("Fatal error: Call to undefined method stdObject::{$method}()");
    }
  }
}

// create PDO prepared statements
$db = new stdObject();

// preflight
$db->get_web_session_info_by_sessionid = $pdo->prepare("SELECT * FROM web_session WHERE sessionid = :sessionid");
$db->update_web_session_info_by_sessionid = $pdo->prepare("UPDATE web_session SET expires = :expires WHERE sessionid = :sessionid");
$db->create_web_session_info = $pdo->prepare("INSERT INTO web_session (sessionid, expires, metadata) VALUES (:sessionid, :expires, :metadata)");

// signup
$db->create_user = $pdo->prepare("INSERT INTO user (username, passwd, email, valid, modified) VALUES (:username, :passwd, :email, TRUE, :modified)");
$db->create_login_info = $pdo->prepare("INSERT INTO user_login (username, salt, challenge, expires) VALUES (:username, :salt, NULL, NULL)");

$db->create_user_transaction = function ($stdObject, $username, $passwd, $email, $modified, $salt, &$db, &$pdo) {
  try {
    $pdo->beginTransaction();

    $db->create_user->execute(array(
      'username' => $username,
      'passwd' => $passwd,
      'email' => $email,
      'modified' => $modified
    ));

    $db->create_login_info->execute(array(
      'username' => $username,
      'salt' => $salt
    ));

    $pdo->commit();

    return true;
  } catch (Exception $e) {
    $pdo->rollback();
    log_to_console($e->getMessage());

    return false;
  }
};

// identify
$db->get_login_info_by_username = $pdo->prepare("SELECT valid, salt, challenge, expires FROM user LEFT OUTER JOIN user_login USING (username) WHERE username = :username");
$db->update_login_info_by_username = $pdo->prepare("UPDATE user_login SET challenge = :challenge, expires = :expires WHERE username = :username");

// login
$db->get_user_info_by_username = $pdo->prepare("SELECT passwd, valid, challenge, expires FROM user LEFT OUTER JOIN user_login USING (username) WHERE username = :username");
$db->create_or_update_user_session_info = $pdo->prepare("INSERT INTO user_session (sessionid, username, expires) VALUES (:sessionid, :username, :expires) ON CONFLICT (username) DO UPDATE SET sessionid = :sessionid, expires = :expires");

$request = new Request($decoded_post_body);
$response = null;

// Arbitrate connections to different handler functions
// We only use POST -- this is mostly due to how PHP works
if ($request_method == "POST") {
  if (in_array("preflight", $url_params, STRICT_TYPES)) {
    $response = new Response("preflight");
    preflight($request, $response, $db, $pdo);
  } else if (in_array("signup", $url_params, STRICT_TYPES)) {
    $response = new Response("signup");
    if (preflight($request, $response, $db, $pdo)) {
      signup($request, $response, $db, $pdo);
    }
  } else if (in_array("identify", $url_params, STRICT_TYPES)) {
    $response = new Response("identify");
    if (preflight($request, $response, $db, $pdo)) {
      identify($request, $response, $db, $pdo);
    }
  } else if (in_array("login", $url_params, STRICT_TYPES)) {
    $response = new Response("login");
    if (preflight($request, $response, $db, $pdo)) {
      login($request, $response, $db, $pdo);
    }
  } else if (in_array("sites", $url_params, STRICT_TYPES)) {
    $response = new Response("sites");
    if (preflight($request, $response, $db, $pdo)) {
      sites($request, $response, $db, $pdo);
    }
  } else if (in_array("save", $url_params, STRICT_TYPES)) {
    $response = new Response("save");
    if (preflight($request, $response, $db, $pdo)) {
      save($request, $response, $db, $pdo);
    }
  } else if (in_array("load", $url_params, STRICT_TYPES)) {
    $response = new Response("load");
    if (preflight($request, $response, $db, $pdo)) {
      load($request, $response, $db, $pdo);
    }
  } else if (in_array("logout", $url_params, STRICT_TYPES)) {
    $response = new Response("logout");
    if (preflight($request, $response, $db, $pdo)) {
      logout($request, $response, $db, $pdo);
    }
  } else {
    $response = new Response("default");
    $response->set_http_code(404); // Not found
    $response->failure("Resource not found");
  }
}

// This is an easy way to test functionality
// To run the code in this block, just make a request to localhost:8000/server.php?test
if (in_array("test", $url_params)) {
  // echo phpinfo();
}

// Set response code
http_response_code($response->get_http_code());
// Set response headers
header("Content-Type: application/json");
header("Cache-Control: no-cache, must-revalidate");
// Set any cookies
foreach ($response->get_cookies() as $cookie) {
  // name, value, expires, path, domain, secure, httponly
  // This will set a cookie that is inaccessible to JavaScript on modern browsers
  setcookie($cookie["name"], $cookie["value"], $cookie["expires"], COOKIE_PATH, COOKIE_DOMAIN, NOT_SECURE, HTTP_ONLY);
}
// Echo out the JSON encoded response body
echo $response->json();
