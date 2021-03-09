<?php

require_once('db.php');
require_once('../model/Response.php');

/**
 * @author Steve Labrinos [stalab at linuxmail.org] on 8/3/2021
 */

try {
    $writeDB = DB::connectWriteDB();
} catch (PDOException $ex) {
    error_log("Connection error ".$ex, 0);

    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Database connection error");
    $response->send();
    exit;
}

if (array_key_exists("sessionid", $_GET)) {
    $sessionId = $_GET['sessionid'];

    if ($sessionId === '' || !is_numeric($sessionId)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $sessionId === '' ? $response->addMessage("Session ID cannot be blank") : false;
        !is_numeric($sessionId) ? $response->addMessage("Session ID must be a number") : false;
        $response->send();
        exit;
    }

    //  check the Authorization in the header
    if (!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1) {
        $response = new Response();
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        !isset($_SERVER['HTTP_AUTHORIZATION']) ? $response->addMessage("Access token is missing from th header") : false;
        strlen($_SERVER['HTTP_AUTHORIZATION']) < 1 ? $response->addMessage("Access token cannot be blank") : false;
        $response->send();
        exit;
    }

    $accessToken = $_SERVER['HTTP_AUTHORIZATION'];

    //  sessions/3 - PATCH refresh session
    if ($_SERVER['REQUEST_METHOD'] === 'PATCH') {
        //  the logic provies with a new refresh token after checking the access token expiration time
        //  the refresh token is provided in th json body

        //  check content type
        if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage("Content type header not set to JSON");
            $response->send();
            exit;
        }

        //  check that the request body is valid JSON
        $rawPATCHData = file_get_contents('php://input');

        if (!$jsonData = json_decode($rawPATCHData)) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage("Request body is not valid JSON");
            $response->send();
            exit;
        }

        //  check that the refresh token exists
        if (!isset($jsonData->refresh_token) || strlen($jsonData->refresh_token) < 1) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            !isset($jsonData->refresh_token) ? $response->addMessage("Refresh token is not supplied") : false;
            strlen($jsonData->refresh_token) < 1 ? $response->addMessage("Refresh token cannot be black") : false;
            $response->send();
            exit;
        }

        //  query
        try {
            $refreshToken = $jsonData->refresh_token;

            //  need to join users and session table
            $query = 'SELECT s.id session_id, 
                             s.userid user_id, 
                             accesstoken, 
                             refreshtoken, 
                             user_active, 
                             login_attempts, 
                             accesstokenexpiry, 
                             refreshtokenexpiry
                      FROM tblsessions s JOIN tblusers u ON s.userid = u.id
                      WHERE s.id = :sessionId
                      AND s.accesstoken = :accessToken
                      AND s.refreshtoken = :refreshToken';
            $stmt = $writeDB->prepare($query);
            $stmt->bindParam(':sessionId', $sessionId, PDO::PARAM_INT);
            $stmt->bindParam(':accessToken', $accessToken, PDO::PARAM_STR);
            $stmt->bindParam(':refreshToken', $refreshToken, PDO::PARAM_STR);
            $stmt->execute();

            $rowCount = $stmt->rowCount();

            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage("Access token or refresh token is incorrect for session ID");
                $response->send();
                exit;
            }

            //  store returned data in variables
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $returnedSessionId = $row['session_id'];
            $returnedUserId = $row['user_id'];
            $returnedAccessToken = $row['accesstoken'];
            $reutrnedRefreshToken = $row['refreshtoken'];
            $returnedUserActive = $row['user_active'];
            $returnedLoginAttempts = $row['login_attempts'];
            $returnedAccessTokenExpiry = $row['accesstokenexpiry'];
            $returnedRefreshTokenExpiry = $row['refreshtokenexpiry'];

            //  check that the user is active
            if ($returnedUserActive !== 'Y') {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage("User is not active");
                $response->send();
                exit;
            }

            //  check that the login attempts
            if ($returnedLoginAttempts >= 3) {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage("User account is currently locked out");
                $response->send();
                exit;
            }

            //  check that the refresh token is not expired
            if (strtotime($returnedRefreshTokenExpiry) < time()) {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage("Refresh token has expired - Please log in again");
                $response->send();
                exit;
            }

            //  regenerate a new access and refresh token
            $accessToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)).time());
            $refreshToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)).time());

            $accessTokenExpirySeconds = 1200;
            $refreshTokenExpirySeconds = 1209600;

            //  update the current session
            $query = 'UPDATE tblsessions
                      SET   accesstoken = :accessToken,
                            refreshtoken = :refreshToken,
                            accesstokenexpiry = date_add(NOW(), INTERVAL :accessTokenExpirySeconds SECOND),
                            refreshtokenexpiry = date_add(NOW(), INTERVAL :refreshTokenExpirySeconds SECOND)
                      WHERE id = :sessionId
                      AND userid = :userId
                      AND accesstoken = :returnedAccessToken
                      AND refreshtoken = :returnedRefreshToken';
            $stmt = $writeDB->prepare($query);
            $stmt->bindParam(':accessToken', $accessToken, PDO::PARAM_STR);
            $stmt->bindParam(':refreshToken', $refreshToken, PDO::PARAM_STR);
            $stmt->bindParam(':accessTokenExpirySeconds', $accessTokenExpirySeconds, PDO::PARAM_INT);
            $stmt->bindParam(':refreshTokenExpirySeconds', $refreshTokenExpirySeconds, PDO::PARAM_INT);
            $stmt->bindParam(':sessionId', $returnedSessionId, PDO::PARAM_INT);
            $stmt->bindParam(':userId', $returnedUserId, PDO::PARAM_INT);
            $stmt->bindParam(':returnedAccessToken', $returnedAccessToken, PDO::PARAM_STR);
            $stmt->bindParam(':returnedRefreshToken', $reutrnedRefreshToken, PDO::PARAM_STR);
            $stmt->execute();

            $rowCount = $stmt->rowCount();

            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage("Access token counld not be refreshed - please log in again");
                $response->send();
                exit;
            }

            //  send the response back
            $returnData = array(
                "session_id" => $returnedSessionId,
                "access_token" => $accessToken,
                "access_token_expiry" => $accessTokenExpirySeconds,
                "refresh_token" => $refreshToken,
                "refresh_token_expiry" => $refreshTokenExpirySeconds
            );

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage("Token refreshed");
            $response->setData($returnData);
            $response->send();
            exit;
        } catch (PDOException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("There was an issue refreshing action token - Please login again".$ex->getMessage());
            $response->send();
            exit;
        }
    }
    //  sessions/3 - DELETE
    elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
        try {
            $query = 'DELETE FROM tblsessions
                      WHERE id = :sessionId
                      AND accesstoken = :accessToken';
            $stmt = $writeDB->prepare($query);
            $stmt->bindParam(':sessionId', $sessionId, PDO::PARAM_INT);
            $stmt->bindParam(':accessToken', $accessToken, PDO::PARAM_STR);
            $stmt->execute();

            $rowCount = $stmt->rowCount();

            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Failed to log out of this session using token provided");
                $response->send();
                exit;
            } 

            //  response for log out
            $returnData = array(
                "session_id" => intval($sessionId)
            );

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage("Logged out");
            $response->setData($returnData);
            $response->send();
            exit;
        } catch (PDOException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("There was an issue loggin out. Please try again");
            $response->send();
            exit;
        }
    }
    //  unsupported method
    else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage("Request method is not allowed");
        $response->send();
        exit;
    }
}
//  sessions    - POST create a session
elseif (empty($_GET)) {
    //  only accept POST method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage("Request method not allowed");
        $response->send();
        exit;
    } 

    //  help to prevent a brute force attacks
    sleep(0.2);

    //  check that the body is json
    if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Content type header not set to json");
        $response->send();
        exit;
    }

    //  check for valid json
    $rawPOSTData = file_get_contents('php://input');
    if (!$jsonData = json_decode($rawPOSTData)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Post body is not valid json");
        $response->send();
        exit;
    }

    //  data validation with mandatoty fields
    if (!isset($jsonData->username) || !isset($jsonData->password)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        !isset($jsonData->username) ? $response->addMessage("Username not supplied") : false;
        !isset($jsonData->password) ? $response->addMessage("Password not supplied") : false;
        $response->send();
        exit;
    }

    //  validate the parammeters min and max length
    if (strlen($jsonData->username) < 0 || strlen($jsonData->password) < 0 ||
        strlen($jsonData->username) > 255 || strlen($jsonData->password) > 255) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        strlen($jsonData->username) < 0 ? $response->addMessage("Username can't be bank") : false;
        strlen($jsonData->username) > 255 ? $response->addMessage("Username can't be greather than 255 characters") : false;
        strlen($jsonData->password) < 0 ? $response->addMessage("Password can't be bank") : false;
        strlen($jsonData->password) > 255 ? $response->addMessage("Password can't be greather than 255 characters") : false;
        $response->send();
        exit;
    }

    try {
        //  prepare the user input to query the DB
        $username = trim($jsonData->username);
        $password = $jsonData->password;

        $query = 'SELECT id, fullname, username, password, user_active, login_attempts
                  FROM tblusers
                  WHERE username = :username';
        $stmt = $writeDB->prepare($query);
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->execute();
        
        //  must return 1 row because username is unique
        $rowCount = $stmt->rowCount();

        if ($rowCount === 0) {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage("Username or password is incorrect");
            $response->send();
            exit;
        } 

        //  retrieve stored data to perform validations
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        $returnedId = $row['id'];
        $returnedFullname = $row['fullname'];
        $returnedUsername = $row['username'];
        $returnedPassword = $row['password'];
        $returnedUserActive = $row['user_active'];
        $returnedLoginAttempts = $row['login_attempts'];

        //  check that the user is active
        if ($returnedUserActive !== 'Y') {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage("User account not active");
            $response->send();
            exit;
        }

        //  check and compute the login attempts
        if ($returnedLoginAttempts >= 3) {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage("User account is currently locked out");
            $response->send();
            exit;
        } 

        //  verify the password with the returned hashed password
        if (!password_verify($password, $returnedPassword)) {
            //  increment the login attempts
            $query = 'UPDATE tblusers
                      SET login_attempts = login_attempts + 1
                      WHERE id = :id';
            $stmt = $writeDB->prepare($query);
            $stmt->bindParam(':id', $returnedId, PDO::PARAM_INT);
            $stmt->execute();

            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage("Username or password is incorrect");
            $response->send();
            exit;
        }
        
        //  create a new session
        //  generate radom tokens
        $accessToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)).time());
        $refreshToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)).time());

        $accessTokenExpirySeconds = 1200;       //20 minutes
        $refreshTokenExpirySeconds = 1209600;   //14 days
    } catch (PDOException $ex) {
        error_log("Database error ".$ex, 0);

        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("Error quering the DataBase");
        $response->send();
        exit;
    }

    //  after generating the tokens 2 actions to the DB are performed
    //  in new try block, to create a savepoint if one of them fails
    try {
        //  create an atonomous block of transactions
        $writeDB->beginTransaction();

        //  1rst query reset the login attempts
        $query = 'UPDATE tblusers
                  SET login_attempts = 0
                  WHERE id = :id';
        $stmt = $writeDB->prepare($query);
        $stmt->bindParam(':id', $returnedId, PDO::PARAM_INT);
        $stmt->execute();

        //  2nd query for inserting a new session
        $query = 'INSERT INTO tblsessions (userid, accesstoken, accesstokenexpiry, refreshtoken, refreshtokenexpiry)
                  VALUES (:userid, 
                          :accessToken, 
                          date_add(NOW(), INTERVAL :accessTokenExpiry SECOND), 
                          :refreshToken, 
                          date_add(NOW(), INTERVAL :refreshTokenExpiry SECOND))';
        $stmt = $writeDB->prepare($query);
        $stmt->bindParam(':userid', $returnedId, PDO::PARAM_INT);
        $stmt->bindParam(':accessToken', $accessToken, PDO::PARAM_STR);          
        $stmt->bindParam(':accessTokenExpiry', $accessTokenExpirySeconds, PDO::PARAM_INT);          
        $stmt->bindParam(':refreshToken', $refreshToken, PDO::PARAM_STR); 
        $stmt->bindParam(':refreshTokenExpiry', $refreshTokenExpirySeconds, PDO::PARAM_INT);  
        $stmt->execute();                 

        //  return the new session id
        $returnedSessionId = $writeDB->lastInsertId();

        //  complete the transaction by commiting
        $writeDB->commit();

        //  return the inserted data
        $returnData = array(
            "session_id" => $returnedSessionId,
            "access_token" => $accessToken,
            "access_token_expires_in" => $accessTokenExpirySeconds,
            "refresh_token" => $refreshToken,
            "refresh_token_expires_in" => $refreshTokenExpirySeconds
        );

        $response = new Response();
        $response->setHttpStatusCode(201);
        $response->setSuccess(true);
        $response->setData($returnData);
        $response->send();
        exit;
    } catch (PDOException $ex) {
        error_log("Database error ".$ex, 0);
        $writeDB->rollBack();
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("There was an issue logging in. Please try again");
        $response->send();
        exit;
    }
}
//  404 for invalid roots
else {
    $response = new Response();
    $response->setHttpStatusCode(404);
    $response->setSuccess(false);
    $response->addMessage("Endpoint for sessions not found");
    $response->send();
    exit;
}