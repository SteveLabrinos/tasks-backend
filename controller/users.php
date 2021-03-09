<?php

require_once('db.php');
require_once('../model/Response.php');

/**
 * @author Steve Labrinos [stalab at linuxmail.org] on 6/3/2021
 */

//  always use the writeDB

try {
    $writeDB = DB::connectWriteDB();
} catch (PDOException $ex) {
    error_log("connection error".$ex, 0);

    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Unable to connect");
    $response->send();
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response = new Response();
    $response->setHttpStatusCode(405);
    $response->setSuccess(false);
    $response->addMessage("Request method not allowed");
    $response->send();
    exit;
}

if ($_SERVER['CONTENT_TYPE'] === 'Application/json') {
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    $response->addMessage("Content type header not set to json");
    $response->send();
    exit;
}

$rawPOSTData = file_get_contents('php://input');

if (!$jsonData = json_decode($rawPOSTData)) {
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    $response->addMessage("Request body is not valid json");
    $response->send();
    exit;
}

if (!isset($jsonData->fullname) || !isset($jsonData->username) || !isset($jsonData->password)) {
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    !isset($jsonData->fullname) ? $response->addMessage("Fullname is not supplied") : false;
    !isset($jsonData->username) ? $response->addMessage("Username is not supplied") : false;
    !isset($jsonData->password) ? $response->addMessage("Password is not supplied") : false;
    $response->send();
    exit;
}

//  check valid data
if (strlen($jsonData->fullname) < 1 || strlen($jsonData->fullname) > 255 ||
strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255 ||
strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255) {
    $response = new Response();
    $response->setHttpStatusCode(400);
    $response->setSuccess(false);
    strlen($jsonData->fullname) < 1 ? $response->addMessage("Fullname cannot be blank") : false;
    strlen($jsonData->fullname) > 255 ? $response->addMessage("Fullname cannot be greater than 255 chars") : false;
    strlen($jsonData->username) < 1 ? $response->addMessage("Username cannot be blank") : false;
    strlen($jsonData->username) > 255 ? $response->addMessage("Username cannot be greater than 255 chars") : false;    $response->send();
    strlen($jsonData->password) < 1 ? $response->addMessage("Password cannot be blank") : false;
    strlen($jsonData->password) > 255 ? $response->addMessage("Password cannot be greater than 255 chars") : false;
    exit;
}

//  trim the provided values
$fullname = trim($jsonData->fullname);
$username = trim($jsonData->username);
$password = $jsonData->password;

//  chack for the unique validation of username
try {
    $query = 'SELECT id
              FROM tblusers
              WHERE username = :username';
    $stmt = $writeDB->prepare($query);
    $stmt->bindParam(':username', $username, PDO::PARAM_STR);
    $stmt->execute();
    
    $rowCount = $stmt->rowCount();

    //  check unique
    if ($rowCount !== 0) {
        $response = new Response();
        $response->setHttpStatusCode(409);
        $response->setSuccess(false);
        $response->addMessage("Username already exists");
        $response->send();
        exit;
    }

    //  insert the provided data
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $query = 'INSERT INTO tblusers (fullname, username, password)
              VALUES (:fullname, :username, :password)';
    $stmt = $writeDB->prepare($query);
    $stmt->bindParam(':fullname', $fullname, PDO::PARAM_STR);
    $stmt->bindParam(':username', $username, PDO::PARAM_STR);
    $stmt->bindParam(':password', $hashed_password, PDO::PARAM_STR);
    $stmt->execute();

    $rowCount = $stmt->rowCount();
    
    //  check if the isert was succesfull
    if ($rowCount === 0) {
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("There was an issue createing a user account. Please try again");
        $response->send();
        exit;
    }

    //  return id, username, fullname after succesful creatinon
    $user_id = $writeDB->lastInsertId();

    $returnData = array(
        "user_id" => $user_id,
        "fullname" => $fullname,
        "username" => $username
    );

    $response = new Response();
    $response->setHttpStatusCode(201);
    $response->setSuccess(true);
    $response->addMessage("User created");
    $response->setData($returnData);
    $response->send();
    exit;
} catch (PDOException $ex) {
    error_log("Database query erro".$ex, 0);

    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("There was an issue createing a user account. Please try again");
    $response->send();
    exit;
}

