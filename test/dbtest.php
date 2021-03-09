<?php

require_once('../controller/db.php');
require_once('../model/Response.php');

/**
 * @return test 
 * @author Steve Labrinos [stalab at linuxmail.org] on 6/3/2021
 */

try {
    $writeDB = DB::connectWriteDB();
    $readDB = DB::connectReadDB();
} catch(PDOException $ex) {
    $response = new Response();

    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Database connection error");
    $response->send();

    exit;
}