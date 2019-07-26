<?php

/******************************************************************************
 * This file contains the server side PHP code that students need to modify
 * to implement the password safe application.  Another PHP file, server.php,
 * should not need to be modified and handles initialization of some variables,
 * resource arbitration, and outputs the reponse.  The last PHP file is api.php
 * which should also not be modified by students and which provides an API
 * for resource functions to communicate with clients.
 *
 * Student code in this file should only interact with the outside world via
 * the parameters to the functions.  These parameters are the same for each
 * function.  The Request and Reponse classes can be found in api.php.
 * For more information on PDO database connections, see the documentation at
 * https://www.php.net/manual/en/book.pdo.php or other websites.
 *
 * The parameters to each function are:
 *   -- $request A Request object, passed by reference (see api.php)
 *   -- $response A Response object, passed by reference (see api.php)
 *   -- $db A PDO database connection, passed by reference
 *
 * The functions must also return the same values.  They are:
 *   -- true on success, false on failure
 *
 * Students should understand how to use the Request and Response objects, so
 * please spend some time looking at the code in api.php.  Apart from those
 * classes, the only other API function that students should use is the
 * log_to_console function, which MUST be used for server-side logging.
 *
 * The functions that need to be implemented all handle a specific type of
 * request from the client.  These map to the resources the client JavaScript
 * will call when the user performs certain actions.
 * The functions are:
 *    - preflight -- This is a special function in that it is called both
 *                   as a separate 'preflight' resource and it is also called
 *                   before every other resource to perform any preflight
 *                   checks and insert any preflight response.  It is
 *                   especially important that preflight returns true if the
 *                   request succeeds and false if something is wrong.
 *                   See server.php to see how preflight is called.
 *    - signup -- This resource should create a new account for the user
 *                if there are no problems with the request.
 *    - identify -- This resource identifies a user and returns any
 *                  information that the client would need to log in.  You
 *                  should be especially careful not to leak any information
 *                  through this resource.
 *    - login -- This resource checks user credentials and, if they are valid,
 *               creates a new session.
 *    - sites -- This resource should return a list of sites that are saved
 *               for a logged in user.  This result is used to populate the
 *               dropdown select elements in the user interface.
 *    - save -- This resource saves a new (or replaces an existing) entry in
 *              the password safe for a logged in user.
 *    - load -- This resource loads an existing entry from the password safe
 *              for a logged in user.
 *    - logout -- This resource should destroy the existing user session.
 *
 * It is VERY important that resources set appropriate HTTP response codes!
 * If a resource returns a 5xx code (which is the default and also what PHP
 * will set if there is an error executing the script) then I will assume
 * there is a bug in the program during grading.  Similarly, if a resource
 * returns a 2xx code when it should fail, or a 4xx code when it should
 * succeed, then I will assume it has done the wrong thing.
 *
 * You should not worry about the database getting full of old entries, so
 * don't feel the need to delete expired or invalid entries at any point.
 *
 * The database connection is to the sqlite3 database 'passwordsafe.db'.
 * The commands to create this database (and therefore its schema) can
 * be found in 'initdb.sql'.  You should familiarize yourself with this
 * schema.  Not every table or field must be used, but there are many
 * helpful hints contained therein.
 * The database can be accessed to run queries on it with the command:
 *    sqlite3 passwordsafe.db
 * It is also easy to run SQL scripts on it by sending them to STDIN.
 *    sqlite3 passwordsafe.db < myscript.sql
 * This database can be recreated (to clean it up) by running:
 *    sqlite3 passwordsafe.db < dropdb.sql
 *    sqlite3 passwordsafe.db < initdb.sql
 *
 * This is outlined in more detail in api.php, but the Response object
 * has a few methods you will need to use:
 *    - set_http_code -- sets the HTTP response code (an integer)
 *    - success       -- sets a success status message
 *    - failure       -- sets a failure status message
 *    - set_data      -- returns arbitrary data to the client (in json)
 *    - set_cookie    -- sets an HTTP-only cookie on the client that
 *                       will automatically be returned with every
 *                       subsequent request.
 *    - delete_cookie -- tells the client to delete a cookie.
 *    - set_token     -- passes a token (via data, not headers) to the
 *                       client that will automatically be returned with
 *                       every subsequent request.
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * To get the current date and time in a format the database expects:
 *      $now = new DateTime();
 *      $now->format(DateTimeInterface::ISO8601);
 *
 * To get a date and time 15 minutes in the future (for the database):
 *      $now = new DateTime();
 *      $interval = new DateInterval('PT15M');
 *      $now->add($interval)->format(DateTimeInterface::ISO8601);
 *
 * Notice that, like JavaScript, PHP is loosely typed.  A common paradigm in
 * PHP is for a function to return some data on success or false on failure.
 * Care should be taken with these functions to test for failure using ===
 * (as in, if($result !== false ) {...}) because not using === or !== may
 * result in unexpected ceorcion of a valid response (0) to false.
 *
 *****************************************************************************/


/**
 * Performs any resource agnostic preflight validation and can set generic response values.
 * If the request fails any checks, preflight should return false and set appropriate
 * HTTP response codes and a failure message.  Returning false will prevent the requested
 * resource from being called.
 */
function preflight(&$request, &$response, &$db, &$pdo)
{
  $is_new_sessionid_required = false;
  $sessionid = $request->cookie('sessionid');

  // Check if sessionid is in cookies
  if ($sessionid) {
    $get_web_session_info_by_sessionid = $db->get_web_session_info_by_sessionid;
    $get_web_session_info_by_sessionid->execute(array('sessionid' => $sessionid));
    $web_session = $get_web_session_info_by_sessionid->fetch();

    // Check if sessionid exists in db and is not expired
    if ($web_session && new DateTime() < date_create_from_format(DateTimeInterface::ISO8601, $web_session['expires'])) {
      $csrf_token = $request->token('csrf_token');

      // Check if csrf_token exists and if it is valid, update expires
      if ($csrf_token && $csrf_token === $web_session['metadata']) {
        $expires = new DateTime('+30 minutes');
        $expires = $expires->format(DateTimeInterface::ISO8601);

        $db->update_web_session_info_by_sessionid->execute(array(
          'expires' => $expires,
          'sessionid' => $sessionid
        ));

        log_to_console('Updated web session!');
      } else {
        // This is possible CSRF, void session, reject request and log client IP
        $expires = new DateTime('-30 minutes');
        $expires = $expires->format(DateTimeInterface::ISO8601);

        $db->update_web_session_info_by_sessionid->execute(array(
          'expires' => $expires,
          'sessionid' => $sessionid
        ));

        $response->delete_cookie('sessionid');
        $response->set_http_code(403);
        $response->failure('Request Failed');
        log_to_console('Possible CSRF from ' . $request->client_ip() . '!');

        return false;
      }
    } else {
      $is_new_sessionid_required = true;
    }
  } else {
    $is_new_sessionid_required = true;
  }

  if ($is_new_sessionid_required) {
    // Create new sessionid and csrf_token
    $sessionid = trim(get_guid(), '{}');
    $expires = new DateTime('+30 minutes');
    $expires = $expires->format(DateTimeInterface::ISO8601);
    $csrf_token = trim(get_guid(), '{}');

    $db->create_web_session_info->execute(array(
      'sessionid' => $sessionid,
      'expires' => $expires,
      'metadata' => $csrf_token
    ));

    $response->add_cookie('sessionid', $sessionid);
    $response->set_token('csrf_token', $csrf_token);

    log_to_console('New web session created.');
  }

  $response->set_http_code(200);
  $response->success('Request OK');

  return true;
}

/**
 * Tries to sign up the username with the email and password.
 * The username and email must be unique and valid, and the password must be valid.
 * Note that it is fine to rely on database constraints.
 */
function signup(&$request, &$response, &$db, &$pdo)
{
  $username = $request->param('username'); // The requested username from the client
  $password = $request->param('password'); // The requested password from the client
  $email    = $request->param('email');    // The requested email address from the client

  // Check if params are valid
  if (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-_]{2,20}$/', $username) === 0) {
    $response->set_http_code(400);
    $response->failure('Username is invalid!');
    log_to_console('Username is invalid!');

    return false;
  } else if (preg_match('/^[A-Fa-f0-9]{64}$/', $password) === 0) {
    $response->set_http_code(400);
    $response->failure('Password is invalid!');
    log_to_console('Password is invalid!');

    return false;
  } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $response->set_http_code(400);
    $response->failure('Email is invalid!');
    log_to_console('Email is invalid!');

    return false;
  }

  // Convert to lower case
  $username = strtolower($username);
  $password = strtolower($password);
  $email = strtolower($email);

  // Hash password with salt
  $salt = md5(uniqid(rand())) . md5(uniqid(rand()));
  $password = hash('sha256', $password .= $salt);

  // generate timestamp
  $modified = new DateTime();
  $modified = $modified->format(DateTimeInterface::ISO8601);

  if (!$db->create_user_transaction($username, $password, $email, $modified, $salt, $db, $pdo)) {
    $response->set_http_code(400);
    $response->failure('Failed to create account.');

    return false;
  }

  // Respond with a message of success.
  $response->set_http_code(201); // Created
  $response->success('Account created.');
  log_to_console('Account created.');

  return true;
}

/**
 * Handles identification requests.
 * This resource should return any information the client will need to produce
 * a log in attempt for the given user.
 * Care should be taken not to leak information!
 */
function identify(&$request, &$response, &$db, &$pdo)
{
  $username = $request->param('username'); // The username
  $username = strtolower($username);

  $get_login_info_by_username = $db->get_login_info_by_username;
  $get_login_info_by_username->execute(array('username' => $username));
  $user = $get_login_info_by_username->fetch();

  // Check if user exists
  if ($user) {
    // Check if user is valid
    if ($user['valid'] === '1') {
      // Check if challenge exists and is not expired
      $challenge = $user['challenge'];

      if ($challenge && new DateTime() < date_create_from_format(DateTimeInterface::ISO8601, $user['expires'])) {
        log_to_console('Used existing challenge!');
      } else {
        // Generate new challenge, update expires
        $challenge = md5(uniqid(rand())) . md5(uniqid(rand()));
        $expires = new DateTime('+2 minutes');
        $expires = $expires->format(DateTimeInterface::ISO8601);

        $db->update_login_info_by_username->execute(array(
          'challenge' => $challenge,
          'expires' => $expires,
          'username' => $username
        ));

        log_to_console('Updated challenge!');
      }

      $salt = $user['salt'];
      // Set data
      $response->set_data('salt', $salt);
      $response->set_data('challenge', $challenge);
    } else {
      $response->set_http_code(400);
      $response->failure('Failed to identify user.');
      log_to_console('User is not valid.');

      return false;
    }
  } else {
    $response->set_http_code(400);
    $response->failure('Failed to identify user.');
    log_to_console('User does not exist.');

    return false;
  }

  $response->set_http_code(200);
  $response->success('Successfully identified user.');
  log_to_console('Success.');

  return true;
}

/**
 * Handles login attempts.
 * On success, creates a new session.
 * On failure, fails to create a new session and responds appropriately.
 */
function login(&$request, &$response, &$db, &$pdo)
{
  $username = $request->param('username'); // The username with which to log in
  $password = $request->param('password'); // The password with which to log in
  $username = strtolower($username);
  $password = strtolower($password);

  $get_user_info_by_username = $db->get_user_info_by_username;
  $get_user_info_by_username->execute(array('username' => $username));
  $user = $get_user_info_by_username->fetch();

  // Check if user exists
  if ($user) {
    // Check if user is valid
    if ($user['valid'] === '1') {
      // Check if challenge exists and is not expired
      $challenge = $user['challenge'];

      if ($challenge && new DateTime() < date_create_from_format(DateTimeInterface::ISO8601, $user['expires'])) {
        $password_challenge = hash('sha256', $user['passwd'] . $challenge);

        // Check if password is correct
        if ($password === $password_challenge) {
          $sessionid = $request->cookie('sessionid');
          $expires = new DateTime('+5 minutes');
          $expires = $expires->format(DateTimeInterface::ISO8601);
          $csrf_token = trim(get_guid(), '{}');

          $db->update_web_session_metadata_by_sessionid->execute(array(
            'metadata' => $csrf_token,
            'sessionid' => $sessionid,
          ));

          $response->set_token('csrf_token', $csrf_token);

          $db->create_or_update_user_session_info->execute(array(
            'sessionid' => $sessionid,
            'username' => $username,
            'expires' => $expires
          ));
        } else {
          $response->set_http_code(400);
          $response->failure('Failed to log in.');
          log_to_console('Password is incorrect.');

          return false;
        }
      } else {
        $response->set_http_code(400);
        $response->failure('Failed to log in.');
        log_to_console('Challenge is expired.');

        return false;
      }
    } else {
      $response->set_http_code(400);
      $response->failure('Failed to log in.');
      log_to_console('User is not valid.');

      return false;
    }
  } else {
    $response->set_http_code(400);
    $response->failure('Failed to log in.');
    log_to_console('User does not exist.');

    return false;
  }

  $response->set_http_code(200); // OK
  $response->success('Successfully logged in.');
  log_to_console('User session created.');

  return true;
}

/**
 * Returns the sites for which a password is already stored.
 * If the session is valid, it should return the data.
 * If the session is invalid, it should return 401 unauthorized.
 */
function sites(&$request, &$response, &$db, &$pdo)
{
  $username = get_authenticated_user($request, $response, $db);

  if ($username) {
    $get_sites_data_by_username = $db->get_sites_data_by_username;
    $get_sites_data_by_username->execute(array('username' => $username));
    $sites_data = $get_sites_data_by_username->fetchAll();

    $get_site_attribute = function ($site_data) {
      return $site_data['site'];
    };

    $sites = array_map($get_site_attribute, $sites_data);

    $response->set_data('sites', $sites);
    $response->set_http_code(200);
    $response->success('Sites with recorded passwords.');
    log_to_console('Found and returned sites');

    return true;
  }
}

/**
 * Saves site and password data when passed from the client.
 * If the session is valid, it should save the data, overwriting the site if it exists.
 * If the session is invalid, it should return 401 unauthorized.
 */
function save(&$request, &$response, &$db, &$pdo)
{
  $username = get_authenticated_user($request, $response, $db);

  if ($username) {
    $site       = trim($request->param('site'));
    $siteuser   = trim($request->param('siteuser'));
    $sitepasswd = trim($request->param('sitepasswd'));
    $siteiv     = trim($request->param('siteiv'));

    if ($site !== '' && $sitepasswd !== '' && $siteiv !== '') {
      $modified = new DateTime();
      $modified = $modified->format(DateTimeInterface::ISO8601);

      $db->create_or_update_site_data->execute(array(
        'username' => $username,
        'site' => $site,
        'siteuser' => $siteuser,
        'sitepasswd' => $sitepasswd,
        'siteiv' => $siteiv,
        'modified' => $modified
      ));
    } else {
      $response->set_http_code(400);
      $response->failure('Failed to save invalid site data to safe.');
      log_to_console('Failed to save invalid site data');

      return false;
    }

    $response->set_http_code(200);
    $response->success('Save to safe succeeded.');
    log_to_console('Successfully saved site data');

    return true;
  }
}

/**
 * Gets the data for a specific site and returns it.
 * If the session is valid and the site exists, return the data.
 * If the session is invalid return 401, if the site doesn't exist return 404.
 */
function load(&$request, &$response, &$db, &$pdo)
{
  $username = get_authenticated_user($request, $response, $db);

  if ($username) {
    $site = trim($request->param('site'));

    $get_site_data_by_username_and_site = $db->get_site_data_by_username_and_site;
    $get_site_data_by_username_and_site->execute(array(
      'username' => $username,
      'site' => $site
    ));

    $site_data = $get_site_data_by_username_and_site->fetch();

    if ($site_data) {
      $response->set_data('site', $site_data['site']);
      $response->set_data('siteuser', $site_data['siteuser']);
      $response->set_data('sitepasswd', $site_data['sitepasswd']);
      $response->set_data('siteiv', $site_data['siteiv']);
    } else {
      $response->set_http_code(404);
      $response->failure('Site does not exist.');
      log_to_console('Site does not exist.');

      return false;
    }

    $response->set_http_code(200);
    $response->success('Site data retrieved.');
    log_to_console('Successfully retrieved site data');

    return true;
  }
}

/**
 * Logs out of the current session.
 * Delete the associated session if one exists.
 */
function logout(&$request, &$response, &$db, &$pdo)
{
  $sessionid = $request->cookie('sessionid');
  $get_user_session_info_by_sessionid = $db->get_user_session_info_by_sessionid;
  $get_user_session_info_by_sessionid->execute(array('sessionid' => $sessionid));
  $user_session = $get_user_session_info_by_sessionid->fetch();

  if ($user_session && new DateTime() < date_create_from_format(DateTimeInterface::ISO8601, $user_session['expires'])) {
    $db->delete_user_session_info_by_sessionid->execute(array(
      'sessionid' => $sessionid
    ));

    $response->success('Successfully logged out.');
    log_to_console('Logged out');
  } else {
    $response->success('Please log in first.');
    log_to_console('User has not logged in yet.');
  }

  $response->set_http_code(200);

  return true;
}

// http://guid.us/GUID/PHP
function get_guid()
{
  $charid = strtoupper(md5(uniqid(rand(), true)));
  $hyphen = chr(45); // '-'
  $uuid = chr(123) // '{'
    . substr($charid, 0, 8) . $hyphen
    . substr($charid, 8, 4) . $hyphen
    . substr($charid, 12, 4) . $hyphen
    . substr($charid, 16, 4) . $hyphen
    . substr($charid, 20, 12)
    . chr(125); // '}'
  return $uuid;
}

function get_authenticated_user(&$request, &$response, &$db)
{
  $sessionid = $request->cookie('sessionid');
  $get_user_session_info_by_sessionid = $db->get_user_session_info_by_sessionid;
  $get_user_session_info_by_sessionid->execute(array('sessionid' => $sessionid));
  $user_session = $get_user_session_info_by_sessionid->fetch();

  if ($user_session && new DateTime() < date_create_from_format(DateTimeInterface::ISO8601, $user_session['expires'])) {
    $username = $user_session['username'];
    $expires = new DateTime('+5 minutes');
    $expires = $expires->format(DateTimeInterface::ISO8601);

    $db->create_or_update_user_session_info->execute(array(
      'sessionid' => $sessionid,
      'username' => $username,
      'expires' => $expires
    ));

    log_to_console('Updated user session!');

    return $username;
  } else {
    $response->set_http_code(401);
    $response->failure('Please log in first.');
    log_to_console('Unauthorized access!');

    return false;
  }
}
