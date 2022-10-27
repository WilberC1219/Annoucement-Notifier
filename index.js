/*  If running yourself: */

// 1)make sure to fill in the googleCredentials.json file with client_id and client_secret
// 2)register the redirect uri's and add the scopes I used in googleCredentials.json to your google cloud project
// 3)Create the script on the Apps Script API and deploy it, then link it to your google cloud project
// 4)After linking the Script, you HAVE to create new OAuth Client Id credentials for the project 
//   and use the new client client id
// 5)Add script_id from the script in step 3 to https://script.googleapis.com/v1/scripts/${script_id}:run
//   in googleCredentialstemplate.json file
//
const http = require("http"); 
const https = require("https");
const fs = require("fs");
const qs = require("querystring");
const crypto = require("crypto");
const googleCreds = require("./googleCredentials.json");
const port = 3000;
const server = http.createServer();

let states = [];
server.on("request", connection_handler);
server.listen(port);

function connection_handler(req, res) {
  console.log(`New Request for ${req.url} from ${req.socket.remoteAddress}`);

  if (req.url === "/") {
    const root = fs.createReadStream(`html/introPage.html`);
    res.writeHead(200, { "Content-Type": "text/html" });
    root.pipe(res);
  } 
  else if (req.url.startsWith("/userPrompt")) {
    const main = fs.createReadStream(`html/main.html`);
    res.writeHead(200, { "Content-Type": "text/html" });
    main.pipe(res);
  } 
  else if (req.url.startsWith("/submitted")) {
    const user_input = new URL(req.url, `https://${req.headers.host}`).searchParams;
    if(checkInput(user_input)){ 
	  let user_event = create_Event_Obj(user_input);
      const user_state = crypto.randomBytes(20).toString("hex");
      states.push({ user_event, user_state });
      auth_redirect(user_state, "calendar", res);
    }
	else
		pageNotFound("Invalid Input", 400, res);
  } 
  else if (req.url.startsWith("/cal_authorized"))
	  authorized("calendar", req, res);

  else if (req.url.startsWith("/script_authorized"))
	  authorized("script", req, res);

  else 
  	pageNotFound("Page Not Found", 404, res);
}


/**
 * This function is called when the user has granted
 * for the app permission to add an event to the user's google
 * calender or for the app to send emails out about the event.
 *  
 * @param forApi - A string who's value is either "calendar" or "script". Which
 * will be used to determine What scope and redirect uri to use
 * 
 * @param req - use to create request.
 * 
 * @param res - used to send a response
 */
function authorized(forApi, req, res){
	const url_params = new URL(req.url, `https://${req.headers.host}`).searchParams;
    if (req.url.includes("code")) {
      const user_url_state = {state: url_params.get("state"), auth_code: url_params.get("code")};
      const user_state = states.find((state) => state.user_state === user_url_state.state); 
      if (user_url_state.auth_code != undefined && user_url_state.state != undefined && user_state != undefined) {
        req_AccessToken(user_url_state.auth_code, forApi, user_state, res);
      } 
	  else pageNotFound("Unauthorized", 401, res);
    } 
	else pageNotFound("Unauthorized", 401, res);
}

/**
 * This function will make a POST request to Google's Token endpoint
 * (https://oauth2.googleapis.com/token) so that the application can
 * get an access token.
 *  
 * @param auth_code - The authorization code that was received when the user
 * granted the app permission.
 * 
 * @param forApi - A string who's value is either "calendar" or "script". Which
 * will be used to determine What scope and redirect uri to use
 * 
 * @param user_state - An object that consists of a user_event object and a user's state.
 * 
 * @param res - used to send a response
 */

function req_AccessToken(auth_code, forApi, user_state, res) {
  const accessToken_ep = googleCreds.token_uri;
  const post_data = reqAccessToken_postData(forApi, auth_code);
  const options = {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": post_data.length,
    },
  };
  https
    .request(accessToken_ep, options, (stream) =>
      handle_Stream(stream, receive_AccessToken, forApi, user_state, res)
    )
    .end(post_data);
}

/**
 * Creates the post data body needed to request
 * an access token.
 * 
 * @param auth_code - The authorization code that was received when the user
 * granted the app permission.
 * 
 * @param forApi - A string who's value is either "calendar" or "script". Which
 * will be used to determine What scope and redirect uri to use
 * 
 * 
 */
function reqAccessToken_postData(forApi, auth_code) {
  let api_specific_info;
  if (forApi === "calendar")
    api_specific_info = {
      scope: googleCreds.scopes[1],
      redirect_uri: googleCreds.redirect_uris[0],
    };
  else
    api_specific_info = {
      scope: googleCreds.scopes[0],
      redirect_uri: googleCreds.redirect_uris[1],
    };

  const post_data = {
    code: auth_code,
    client_id: googleCreds.client_id,
    client_secret: googleCreds.client_secret,
    redirect_uri: api_specific_info.redirect_uri,
    grant_type: "authorization_code",
  };
  return qs.stringify(post_data);
}

/**
 * After requesting an access token this function will retrieve 
 * the access token that was returned from making a POST request to 
 * Google's token endpoint (https://oauth2.googleapis.com/token) 
 * Then depending on the value of the parameter forApi either the add_User_Event
 * or send_Email_Script function will be called.
 * 
 * @param body - all the data received from the stream 
 * 
 * @param forApi - A string who's value is either "calendar" or "script". Which
 * will be used to determine what function to exectute. Either add_User_Event
 * or send_Email_Script
 * 
 * @param user_state - A Json object that consists of a user_event object and a user's state.
 * 
 * @param res - used to send a response
 * 
 */
function receive_AccessToken(body, forApi, user_state, res) {
  const { access_token } = JSON.parse(body);
  if (forApi === "calendar") add_User_Event(access_token, user_state, res);
  else send_Email_Script(access_token, user_state.user_event, res);
}

/**
 * After invoking an either the Google Calendar Api or Google Apps Script Api
 * This function will process the response received.
 * 
 * @param body - all the data received from the stream 
 * 
 * @param user_state - An object that consists of a user_event object and a user's state.
 * 
 * @param res - used to send a response
 * 
 * @param repsonseFrom - a string that is either "calendar" or "script". This will be used
 * to determine what to do after receiving a response from either the Google Calendar api
 * or the Google Apps Script Api.
 * 
 */
function received_Api_Response(body, user_state, res, repsonseFrom) {
  const response = JSON.parse(body);
  if (repsonseFrom === "calendar") {
    user_state.user_event.eventLink = response.htmlLink;
    auth_redirect(user_state.user_state, "script", res);
  } else {
    res.writeHead(302, { Location: `${user_state.eventLink}` });
    res.end();
  }
}


/**
 * 
 * This function will be used to redirect the user to Googles oauth 
 * endpoint. The user is sent to that endpoint to grant permission to
 * the app in executing tasks on their behalf on their gmail account.
 * 
 * @param event_State - The state for a particular user
 * 
 * @param forApi - A string who's value is either "calendar" or "script". Which
 * will be used to determine what redirect uri and scope to use when
 * sending the user to Google's Oauth endpoint
 * 
 * @param res - used to send a response
 * 
 */
function auth_redirect(event_State, forApi, res) {
  let redirect_uri_used, scope_used;

  if (forApi === "calendar") {
    redirect_uri_used = googleCreds.redirect_uris[0];
    scope_used = googleCreds.scopes[1];
  } else {
    redirect_uri_used = googleCreds.redirect_uris[1];
    scope_used = googleCreds.scopes[0];
  }

  let query_str = qs.stringify({
    client_id: googleCreds.client_id,
    redirect_uri: redirect_uri_used,
    scope: scope_used,
    state: event_State,
    response_type: "code",
  });
  res.writeHead(302, { Location: `${googleCreds.auth_uri}?${query_str}` });
  res.end();
}


/**
 * 
 * This function will send out an https POST request to
 * use the Google Calendar Api and create an event in the user's
 * google calendar.
 * 
 * @param access_token - The access token tied to the user and the scope
 * being used (https://www.googleapis.com/auth/calendar.events).
 * 
 * @param user_event - A user Event Object. This object contains the 
 * following information: Event Name, Event Description, 
 * Event date, start time, end time, and a list of emails.
 * 
 * @param res - used to send a response
 * 
 */
function add_User_Event(access_token, user_state, res) {
  const event_ep = googleCreds.invoke_calendar_events;
  const post_data = user_Event_PostData(user_state.user_event);
  const options = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${access_token}`,
      Accept: "application/json",
    },
  };
  https
    .request(event_ep, options, (stream) =>
      handle_Stream(stream, received_Api_Response, user_state, res, "calendar")
    )
    .end(JSON.stringify(post_data));
}


/**
 * This function will create the Post body data that is needed
 * to use the Google Calendar Api. The post data is just an 
 * object with information needed to create an event.
 * 
 * @param user_event - A user Event Object. This object contains the 
 * following information: Event Name, Event Description, 
 * Event date, start time, end time, and a list of emails.
 * 
 * @returns a object which contains the information
 * required for the Google Calendar api to create an event
 * 
 */
function user_Event_PostData(user_event) {
  const post_data = {
    calendar_id: "primary",
    summary: user_event.eventName,
    description: user_event.eventDesc,
    start: {
      dateTime: `${user_event.eventDate}T${user_event.startTime}:00-04:00`,
      timeZone: "America/New_York",
    },
    end: {
      dateTime: `${user_event.eventDate}T${user_event.endTime}:00-04:00`,
      timeZone: "America/New_York",
    },
  };
  return post_data;
}


/**
 * 
 * This function will send out an https POST request to
 * use the Google Apps Script Api and send out an email 
 * about the event to the email list the was provided by the user.
 * 
 * @param access_token - The access token tied to the user and the scope
 * being used (https://www.googleapis.com/auth/script.send_mail).
 * 
 * @param user_event - A user Event Object. This object contains the 
 * following information: Event Name, Event Description, 
 * Event date, start time, end time, and a list of emails.
 * 
 * @param res - used to send a response
 * 
 */
function send_Email_Script(access_token, user_event, res) {
  const script_ep = googleCreds.invoke_app_script;
  const post_data = email_Script_PostData(user_event);
  const options = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${access_token}`,
      Accept: "application/json",
    },
  };
  https
    .request(script_ep, options, (stream) =>
      handle_Stream(stream, received_Api_Response, user_event, res, "script")
    )
    .end(JSON.stringify(post_data));
}


/**
 * 
 * This function will create the Post body data that is needed
 * to used the Google Apps Script Api. The post data is just an 
 * object.
 * 
 * @param user_event - A user Event Object. This object contains the 
 * following information: Event Name, Event Description, 
 * Event date, start time, end time, and a list of emails.
 * 
 * @returns an object which contains the information
 * required for the Google Apps Script api to be used 
 */
function email_Script_PostData(user_event) {
  const post_data = {
    function: "sendEmails",
    parameters: [
      user_event.emailTo,
      `${user_event.eventName} on ${user_event.eventDate}`,
      user_event.eventDesc,
    ],
  };
  return post_data;
}

/**
 * creates the user_event object. This object contains the 
 * following information: Event Name, Event Description, 
 * Event date, start time, end time, and a list of emails.
 * 
 * @param user_input - A URL.searchParams object 
 * which is meant to contain the input from the user after 
 * the form was submitted.
 * 
 * @returns a user_event object 
 */
function create_Event_Obj(user_input) {
  let user_event_Obj = {
    eventName: user_input.get("eventName"),
    eventDesc: user_input.get("eventDesc"),
    eventDate: user_input.get("eventDate"),
    startTime: user_input.get("start-time"),
    endTime: user_input.get("end-time"),
    emailTo: user_input.get("emails"),
  };
  return user_event_Obj;
}

/**
 * checks the input that the user entered
 * when the form was submitted to make sure
 * its valid.
 * 
 * @param user_input - A URL.searchParams object 
 * which is meant to contain the input from the user
 * 
 * @return returns true is the input is good. Otherwise is the input
 * is bad then this function will return false;
 */
function checkInput(user_input) {
  let inputStatus = true;
  if( !(user_input.has('eventName') && user_input.has('eventDesc') && user_input.has('eventDate') 
  		&& user_input.has('start-time') && user_input.has('end-time') && user_input.has('emails')))
		  inputStatus = false;
  user_input.forEach((value, name) => {
    if (value.length == 0 || value == null)
		  inputStatus = false;
    else if (name == "start-time") {
      let startTime = new Date();
      let endTime = new Date();
      startTime.setHours(value.substring(0, 2), value.substring(3), 0);
      endTime.setHours(user_input.get('end-time').substring(0, 2), 
	  user_input.get('end-time').substring(3), 0);
      if (startTime.getTime() > endTime.getTime()) 
	  	  inputStatus = false;
    }
  });

  return inputStatus;
}

/**
 * Displays 404 Error page on the users end
 * @param statusCode - the status code of the response
 * @param message -the error message displayed on the user's screen
 * @param res - used to send a response
 */
function pageNotFound(message, statusCode, res) {
  res.writeHead(statusCode, { "Content-Type": "text/html" });
  res.end(`<h1>${statusCode} ${message}</h1>`);
}

/**
 * Handles data coming from a stream
 */
function handle_Stream(stream, callback, ...args) {
  let body = "";
  stream.on("data", (chunk) => (body += chunk));
  stream.on("end", () => callback(body, ...args));
}

server.on("listening", listening_handler);
function listening_handler() {
  console.log(`Now Listening on Port ${port}`);
}
