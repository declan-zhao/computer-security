"use strict";

/*******************************************************************
 * This file should not be modified by students!
 * It provides boilerplate for application functionality and some
 * utility functions.
 *******************************************************************/
var currentPage = "default";


/*******************************************************************
 * This top part of the file contains the utility functions that
 * students will need to use in their code.
 *******************************************************************/

/**
 * This makes a request to the server using the passed parameters.
 * This function returns a promise for the response and json objects.
 */
async function serverRequest(resource, data) {
  data["tokens"] = getTokens();
  var response = await fetch("server.php?" + resource, {
    method: "POST",
    cache: "no-cache",
    credentials: "same-origin",
    redirect: "error",
    headers: {
      "Content-Type": "application/json"
    },
    referrer: "no-referrer",
    body: JSON.stringify(data)
  })

  var json = await response.json();
  setTokens(json);

  // it has to be done this way because json() consumes the body
  return {
    "response": response,
    "json": json
  };
}

/**
 * This function hides all the content divs except for the specified one.
 */
function showContent(page) {
  // First hide all the content divs
  var contentDivs = document.querySelectorAll(".content");
  for (let i = 0; i < contentDivs.length; i++) {
    contentDivs[i].style.display = "none";
  }
  // Remove any status messages
  status("");
  // then show the signup content
  document.getElementById(page).style.display = "block";
  // update the current page
  currentPage = page;
  // update the url
  document.location.hash = "#" + page;
}

/**
 * This displays an error or status message on the page.
 */
function status(message) {
  var messageDialog = document.getElementById("message");
  if (message) {
    messageDialog.textContent = message;
    messageDialog.style.display = "block";
  } else {
    messageDialog.style.display = "none";
  }
}

/**
 * This handles standard server status messages.
 * Use the function by passing in the parameter passed from the
 * promise from a serverRequest.
 */
function serverStatus(response) {
  if ("success" in response.json) {
    status(response.json["success"]);
  } else if ("failure" in response.json) {
    status(response.json["failure"]);
  }
}


/**
 * Takes a typed array (like a Uint8Array) or an ArrayBuffer and
 * returns a hex encoded string for its values.
 */
function bufferToHexString(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

/**
 * Takes a hex encoded string and returns a Uint8Array with the
 * hex decoded into its values.
 */
function hexStringToUint8Array(hexString) {
  return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

/**
 * Takes a typed array (like a Uint8Array) or an ArrayBuffer and
 * returns a string with its values decoded as UTF-8 characters.
 */
function bufferToUtf8(buffer) {
  return new TextDecoder("utf-8").decode(buffer);
}

/**
 * Takes a UTF-8 string and returns a Uint8Array with the character
 * codes as its values.
 */
function utf8ToUint8Array(utf8String) {
  return new TextEncoder("utf-8").encode(utf8String);
}

/*******************************************************************
 * Everything below this comment is boilerplate that students should
 * not call directly.  It is used to handle things like navigation.
 *******************************************************************/

const loader = {
  "save": sites,
  "load": sites,
  "logout": logout
};

/**
 * Sets up the page, provides wrappers for action.
 */
function init() {
  // navigation
  window.onhashchange = navigate;

  // set up the forms
  var contentDivs = document.querySelectorAll(".content");
  for (let i = 0; i < contentDivs.length; i++) {
    let content = contentDivs[i];
    // each content div has at most one form
    let form = content.querySelector("form");
    if (form) {
      // if there is a form, attach a handler
      form.addEventListener("submit", function (event) {
        // get all the input elements
        let inputs = form.querySelectorAll("input, output");

        // call the action function, passing the form as this
        // and the inputs as the parameters
        window[content.id].apply(form, inputs);

        // Prevent form submission
        event.preventDefault();
        event.stopPropagation();
      });
    }
  }

  // call navigate, if it returns true then preflight
  if (navigate()) {
    serverRequest("preflight", {});
  }

}


/**
 * Sets any tokens passed from the server.
 * Tokens are stored using sessionStorage which is origin specific and
 * cleared whenever the tab is closed.
 */
function setTokens(json) {
  if ("tokens" in json) {
    let tokens = [];
    for (let key in json["tokens"]) {
      sessionStorage.setItem(key, json["tokens"][key]);
      tokens.push(key);
    }
    sessionStorage.setItem("tokens", tokens.join(","));
  }
}

/**
 * Gets any tokens passed from the server.
 * Tokens are stored using sessionStorage which is origin specific and
 * cleared whenever the tab is closed.
 */
function getTokens() {
  var keyString = sessionStorage.getItem("tokens");
  var tokens = {};

  if (keyString) {
    let tokenKeys = keyString.split(",");
    for (let i = 0; i < tokenKeys.length; i++) {
      let key = tokenKeys[i];
      tokens[key] = sessionStorage.getItem(key);
    }
  }
  return tokens;
}


/**
 * This function is called after the index page finishes rendering.
 * It is also called when the URL anchor hash changes.
 * The return value is used on page initialization.
 * If no other requests are being made on load, then return true so
 * a preflight request will be sent.  If a request is being made on
 * load, return false and preflight will be bypassed.
 */
function navigate() {
  // First check the url to see if we should show a specific page
  var page = window.location.hash.substring(1),
    inputs;
  if (page === currentPage) {
    return true;
  }

  // clear any inputs
  inputs = document.querySelectorAll("form");
  for (let i = 0; i < inputs.length; i++) {
    inputs[i].reset();
  }

  if (page.length > 0) {
    // navigate to the page
    showContent(page);
    // if there is a data loader function for the page, call it
    if (page in loader) {
      loader[page](page);
      return false;
    }

  } else {
    // For now, just show the login page if no page is specified
    showContent("login");
  }
  return true;
}

/**
 * Called when either the add password or load password page loads.
 * Loads the sites data for the dropdown.  Assumes an active session.
 */
function sites(page) {
  // get the select element
  var select = document.querySelector("#" + page + " select[name=sitelist]");
  // bind a change handler (multiple binds for the same function are NOPs)
  select.addEventListener("change", loadSiteWrapper);

  // call the server to get the sites
  serverRequest("sites", {}).then(function (result) {
    if (result.response.ok) {
      let sites = result.json.sites;
      // delete all but the first option
      let options = select.querySelectorAll("option");
      for (let i = 1; i < options.length; i++) {
        select.removeChild(options[i]);
      }
      // populate the dropdown
      for (let i = 0; i < sites.length; i++) {
        let option = document.createElement("option");
        option.textContent = sites[i];
        select.appendChild(option);
      }
    } else {
      showContent("login");
      serverStatus(result);
    }
  });
}

/**
 * Called when a site dropdown is changed to select a site.
 * This can be called from either the save or load page.
 * This function calls the student code so students don't have to figure out how
 * to get the form elements.
 */
function loadSiteWrapper(event) {
  // get the selected option
  var selected = this.selectedOptions[0],
    site = selected.textContent;

  // get the form in the same page as this Select element
  var node = this;
  while (node != null && !node.className.includes("content")) {
    node = node.parentNode;
  }
  // we got the content div, now get the form
  var form = node.querySelector("form"),
    siteElement = form.querySelector("input[name=site], output[name=site]"),
    userElement = form.querySelector("input[name=siteuser], output[name=siteuser]"),
    passElement = form.querySelector("input[name=sitepasswd], output[name=sitepasswd]");

  // if add new was selected, clear the inputs
  if (selected.value == "default") {
    siteElement.value = "";
    userElement.value = "";
    passElement.value = "";
    return false;
  }

  // otherwise, call the student code mostly the same way form submit code is called
  loadSite.call(form, site, siteElement, userElement, passElement);
}
