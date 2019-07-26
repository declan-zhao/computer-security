"use strict";

/*****************************************************************************
 * This is the JavaScript file that students need to modify to implement the
 * password safe application.  The other file, client.js, should be fine
 * without modification.  That file handles page navigation, event handler
 * binding, token setting/retrieving, preflighting, and provides some
 * utility functions that this file should use for encoding/decoding strings
 * and making server requests.
 *
 * Please do not use any method other than serverRequest to make requests to
 * the server!  It handles a few things including tokens that you should not
 * reimplement.
 *
 * Most of the functions in this file handle a form submission.  These
 * are passed as arguments the input/output DOM elements of the form that was
 * submitted.  The "this" keyword for these functions is the form element
 * itself.  The functions that handle form submissions are:
 *   - login
 *   - signup
 *   - save
 *   - load
 *
 * The other functions are each called for different reasons with different
 * parameters:
 *   - loadSite -- This function is called to populate the input or output
 *                 elements of the add or load password form.   The function
 *                 takes the site to load (a string) and the form elements
 *                 as parameters.
 *   - logout -- This function is called when the logout link is clicked.
 *               It should clean up any data and inform the server to log
 *               out the user.
 *   - credentials -- This is a utility function meant to be used by the
 *                    login function.  It is not called from other client
 *                    code (in client.js)!  The purpose of providing the
 *                    outline of this function is to help guide students
 *                    towards an implementation that is not too complicated
 *                    and to give ideas about how some steps can be
 *                    accomplished.
 *
 * The utility functions in client.js are:
 *   - serverRequest -- Takes the server resource and parameters as arguments
 *                      and returns a promise with two properties:
 *                        * response (a JavaScript response object)
 *                        * json (the decoded data from the server)
 *   - showContent -- Shows the specified page of the application.  This is
 *                    how student code should redirect the site to other
 *                    pages after a user action.
 *   - status -- displays a status message at the top of the page.
 *   - serverStatus -- Takes the result of the serverRequest promise and
 *                     displays any status messages from it.  This just
 *                     avoids some code duplication.
 *   - bufferToHexString
 *   - hexStringToUint8Array
 *   - bufferToUtf8
 *   - utf8ToUint8Array
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * Look at the MDN documentation for subtle crypto!
 *      https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
 * Also, you may want to use:
 *      https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
 *
 * The subtle crypto error messages are useless.  Typical errors are due to
 * passing unexpected parameters to the functions.  Take a look at the files
 * from Tutorial 4 for examples of using
 *      crypto.subtle.importKey
 *      crypto.subtle.sign
 *      crypto.subtle.decrypt
 * You may also be interested in using
 *      crypto.subtle.encrypt
 *      crypto.subtle.digest
 *
 * The most common error is to pass a key or iv buffer that is the wrong size.
 * For AES-CBC, for example, the key must be length 16 or 32 bytes, and the
 * IV must be 16 bytes.
 *
 * To concatenate two typed Uint8Arrays (a1, a2), you can do the following:
 *      let a3 = new Uint8Array(a1.length + a2.length);
 *      a3.set(a1);
 *      a3.set(a2, a1.length);
 *
 *****************************************************************************/


/**
 * This is an async function that should return the username and password to send
 * to the server for login credentials.
 */
async function credentials(username) {
  var idResult;

  // get any information needed to log in
  idResult = await serverRequest("identify", {
    "username": username
  });
  // bail if something went wrong
  if (!idResult.response.ok) {
    serverStatus(idResult);
    return 0;
  }

  return idResult.json;
}

/**
 * Called when the user submits the log-in form.
 */
async function login(userInput, passInput) {
  // get the form fields
  var username = userInput.value,
    password = passInput.value;

  const idJson = await credentials(username);

  if (idJson === 0) {
    return;
  }

  // Hash password
  let hashedPassword = await hashMessage(username + password);
  hashedPassword = await hashMessage(hashedPassword + idJson['salt']);
  hashedPassword = await hashMessage(hashedPassword + idJson['challenge']);

  // Send a login request to the server.
  const result = await serverRequest("login", {
    "username": username,
    "password": hashedPassword
  });

  // If the login was successful, show the dashboard.
  if (result.response.ok) {
    const encryptionKey = await hashMessage(password);

    sessionStorage.setItem('encryption_key', encryptionKey);

    showContent("dashboard");
  } else {
    // If the login failed, show the login page with an error message.
    serverStatus(result);
  }
}

/**
 * Called when the user submits the signup form.
 */
async function signup(userInput, passInput, passInput2, emailInput) {
  // get the form fields
  var username = userInput.value,
    password = passInput.value,
    password2 = passInput2.value,
    email = emailInput.value;

  // checking is done with HTML and functions at the end of the file
  // hash password with username
  password = await hashMessage(username + password);

  // send the signup form to the server
  const result = await serverRequest("signup", {
    "username": username,
    "password": password,
    "email": email
  });

  if (result.response.ok) {
    // go to the login page
    showContent("login");
  }
  // show the status message from the server
  serverStatus(result);
}


/**
 * Called when the add password form is submitted.
 */
async function save(siteInput, userInput, passInput) {
  var site = siteInput.value,
    siteuser = userInput.value,
    sitepasswd = passInput.value;

  const rawKey = sessionStorage.getItem('encryption_key');
  const key = await importKey(rawKey);
  const {
    encryptedMessage,
    iv
  } = await encryptMessage(sitepasswd, key);

  // send the data, along with the encrypted password, to the server
  const result = await serverRequest("save", {
    "site": site,
    "siteuser": siteuser,
    "sitepasswd": encryptedMessage,
    "siteiv": iv
  });

  if (result.response.ok) {
    // any work after a successful save should be done here
    siteInput.value = '';
    userInput.value = '';
    passInput.value = '';

    // update the sites list
    sites("save");
  }
  // show any server status messages
  serverStatus(result);
}

/**
 * Called when a site dropdown is changed to select a site.
 * This can be called from either the save or load page.
 * Note that, unlike all the other parameters to functions in
 * this file, siteName is a string (the site to load) and not
 * a form element.
 */
async function loadSite(siteName, siteElement, userElement, passElement) {
  const isDecryptionRequired = passElement.tagName === 'INPUT';
  const result = await serverRequest("load", {
    "site": siteName
  });

  if (result.response.ok) {
    siteElement.value = result.json['site'];
    userElement.value = result.json['siteuser'];

    if (isDecryptionRequired) {
      const rawKey = sessionStorage.getItem('encryption_key');
      const key = await importKey(rawKey);
      const decryptedMessage = await decryptMessage(result.json['sitepasswd'], result.json['siteiv'], key);

      passElement.value = decryptedMessage;
    } else {
      passElement.value = result.json['sitepasswd'];

      sessionStorage.setItem('hexiv', result.json['siteiv']);
    }
  } else {
    // on failure, show the login page and display any server status
    showContent("login");
    serverStatus(result);
  }
}

/**
 * Called when the decrypt password button is pressed.
 */
async function load(siteInput, userInput, passInput) {
  const hexiv = sessionStorage.getItem('hexiv');

  if (passInput.value !== '' && hexiv !== null) {
    const rawKey = sessionStorage.getItem('encryption_key');
    const key = await importKey(rawKey);
    const decryptedMessage = await decryptMessage(passInput.value, hexiv, key);

    passInput.value = decryptedMessage;

    sessionStorage.removeItem('hexiv');
  }
}

/**
 * Called when the logout link is clicked.
 */
function logout() {
  // do any preprocessing needed

  // tell the server to log out
  serverRequest("logout", {}).then(function (result) {
    if (result.response.ok) {
      showContent("login");
    }
    serverStatus(result);
  });
}

/**
 * Called when the value in password2 is changed.
 */
function validatePasswordsMatching() {
  const password = document.querySelector("#signup form .field input[name=password]");
  const password2 = document.querySelector("#signup form .field input[name=password2]");

  if (password2.value === "") {
    password2.setCustomValidity("Please confirm password!");
  } else if (password.value !== password2.value) {
    password2.setCustomValidity("Passwords do not match!");
  } else {
    password2.setCustomValidity("");
  }
}

/**
 * Called when the value in email is changed.
 */
function validateEmail() {
  const email = document.querySelector("#signup form .field input[name=email]");
  const emailRegex = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);

  if (email.value === "") {
    email.setCustomValidity("Please enter email!");
  } else if (!emailRegex.test(email.value)) {
    email.setCustomValidity("Must be a valid email address!");
  } else {
    email.setCustomValidity("");
  }
}

/**
 * Called when the sign up submit button is clicked.
 */
function validateSignupInfo() {
  const username = document.querySelector("#signup form .field input[name=username]");
  const password = document.querySelector("#signup form .field input[name=password]");
  const password2 = document.querySelector("#signup form .field input[name=password2]");
  const email = document.querySelector("#signup form .field input[name=email]");
  const usernameRegex = new RegExp(/^[a-zA-Z0-9][a-zA-Z0-9-_]{2,20}$/);
  const passwordRegex = new RegExp(/(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,16}/);
  const emailRegex = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);

  if (!usernameRegex.test(username.value)) {
    console.log("Username is invalid! You can use letters, numbers, - and _. Must start with a letter or a number, and at least 3 and at most 20 characters.");

    return false;
  }

  if (!passwordRegex.test(password.value)) {
    console.log("Password is invalid! Must contain at least one number, one uppercase and one lowercase letter, and at least 6 and at most 16 characters.");

    return false;
  }

  if (password2.value === "") {
    console.log("Please confirm password!");

    return false;
  }

  if (password.value !== password2.value) {
    console.log("Passwords do not match!");

    return false;
  }

  if (email.value === "") {
    console.log("Please enter email!");

    return false;
  }

  if (!emailRegex.test(email.value)) {
    console.log("Must be a valid email address!");

    return false;
  }

  return true;
}

async function hashMessage(message) {
  const data = utf8ToUint8Array(message);
  const digestValue = await window.crypto.subtle.digest('SHA-256', data);

  return bufferToHexString(digestValue);
}

async function encryptMessage(message, key) {
  const data = utf8ToUint8Array(message);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await window.crypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: iv
  }, key, data);

  return {
    encryptedMessage: bufferToHexString(encryptedData),
    iv: bufferToHexString(iv)
  };
}

async function decryptMessage(encryptedMessage, hexiv, key) {
  const data = hexStringToUint8Array(encryptedMessage);
  const iv = hexStringToUint8Array(hexiv);
  const decryptedData = await window.crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: iv
  }, key, data);

  return bufferToUtf8(decryptedData);
}

async function importKey(rawKey) {
  const rawKeyBuffer = hexStringToUint8Array(rawKey);
  const key = await window.crypto.subtle.importKey('raw', rawKeyBuffer, 'AES-GCM', false, ['encrypt', 'decrypt']);

  return key;
}
