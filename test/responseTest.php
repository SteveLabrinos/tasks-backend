<?php
/**
 * @return test 
 * @author Steve Labrinos [stalab at linuxmail.org] on 6/3/2021
 */
require_once('../model/Response.php');

//  init the response

$response = new Response();

#   success response
// $response->setSuccess(true);
// $response->setHttpStatusCode(200);
// $response->addMessage("Test Message 1");
// $response->addMessage("Test Message 2");
// $response->send();

#   error response
$response->setSuccess(false);
$response->setHttpStatusCode(404);
$response->addMessage("Error with value");
$response->send();