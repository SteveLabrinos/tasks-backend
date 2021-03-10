<?php

require_once('db.php');
require_once('../model/Response.php');
require_once('../model/Task.php');

/**
 * @author Steve Labrinos [stalab at linuxmail.org] on 7/3/2021
 */

try {
    $writeDB = DB::connectWriteDB();
    $readDB = DB::connectReadDB();
} catch (PDOException $ex) {
    //  Log the error
    error_log("Connection error - ".$ex, 0);

    //  return an error response
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Database Connection Error");
    $response->send();

    exit;
}

//  Begin the auth script to check that the user is active
//  the login attempts haven't locked him out 
//  and the refresh token has not expired

//  get the action token
if (!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 0) {
    $response = new Response();
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    !isset($_SERVER['HTTP_AUTHORIZATION']) ? $response->addMessage("Access token is missing from  header") : false;
    strlen($_SERVER['HTTP_AUTHORIZATION']) < 0 ? $response->addMessage("Access token cannot be blank") : false;
    $response->send();
    exit;
}

$accessToken = $_SERVER['HTTP_AUTHORIZATION'];

//  retrieve the user credentials for the access token
try {
    $query = 'SELECT userid, user_active, login_attempts, accesstokenexpiry
              FROM tblsessions JOIN tblusers ON tblsessions.userid = tblusers.id
              WHERE accesstoken = :accessToken';
    $stmt = $writeDB->prepare($query);
    $stmt->bindParam(':accessToken', $accessToken, PDO::PARAM_STR);
    $stmt->execute();

    $rowCount = $stmt->rowCount();

    if ($rowCount === 0) {
        $response = new Response();
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        $response->addMessage("Failed to retrieve user credential for the access token");
        $response->send();
        exit;
    }
} catch (PDOException $ex) {
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Failed to execute database query");
    $response->send();
    exit;
}

$row = $stmt->fetch(PDO::FETCH_ASSOC);

$returnUserId = $row['userid'];
$returnUserActive = $row['user_active'];
$returnLoginAttempts = $row['login_attempts'];
$returnAccessTokenExpiry = $row['accesstokenexpiry'];

//  check that the user is active
if ($returnUserActive !== 'Y') {
    $response = new Response();
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    $response->addMessage("User account not active");
    $response->send();
    exit;
}

//  check the number of login attempts
if ($returnLoginAttempts >= 3) {
    $response = new Response();
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    $response->addMessage("User account is locked out");
    $response->send();
    exit;
}

//  check that the access token has not expired
if (strtotime($returnAccessTokenExpiry) < time()) {
    $response = new Response();
    $response->setHttpStatusCode(401);
    $response->setSuccess(false);
    $response->addMessage("Access token expired");
    $response->send();
    exit;
}

//  get a single task
//  url example -> tasks/1
if(array_key_exists("taskid", $_GET)) {
    $taskid = $_GET['taskid'];

    if($taskid == '' || !is_numeric($taskid)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Task ID cannot be blank or must be numeric");
        $response->send();

        exit;
    }

    //  3 actions with a single task GET, INSERT, DELETE
    if($_SERVER['REQUEST_METHOD'] === 'GET') {
        //  query the DB for a single request from the readDB
        try {
            $sql = 'SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") deadline, completed
                    FROM tbltasks
                    WHERE id = :taskid
                    AND userid = :userid';

            $query = $readDB->prepare($sql);
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            //  no data found
            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Task not found");
                $response->send();

                exit;
            }

            //  create new task obj for every row
            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task(
                    $row['id'], 
                    $row['title'], 
                    $row['description'], 
                    $row['deadline'], 
                    $row['completed']
                );

                $taskArray[] = $task->returnTaskAsArray();
            }

            //  prepare the response data
            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();

            exit;
        } catch (PDOException $ex) {
            error_log("DB query error - ".$ex, 0);

            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get task".$ex->getMessage());
            $response->send();

            exit;

        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();

            exit;
        }

    } else if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {

        //  query the DB
        try {
            $sql = 'DELETE FROM tbltasks 
                    WHERE id = :taskid
                    AND userid = :userid';
            $query = $writeDB->prepare($sql);
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            // no data found
            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Task not found");
                $response->send();

                exit;
            }

            //  return the success message
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage("Task deleted");
            $response->send();
        } catch (PDOException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to delete task");
            $response->send();

            exit;
        }

    } else if ($_SERVER['REQUEST_METHOD'] === 'PATCH') {
        //  updating an existing task
        try {
            //  check the content type
            if($_SERVER['CONTENT_TYPE'] !== 'application/json') {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Content type header not set to JSON");
                $response->send();

                exit;
            }

            $rawPATCHData = file_get_contents('php://input');

            if (!$jsonData = json_decode($rawPATCHData)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Request body is not valid JSON");
                $response->send();

                exit;
            }

            //  track the fields that can be updated
            $title_updated = false;
            $description_updated = false;
            $deadline_updated = false;
            $completed_updated = false;

            $queryFields = "";

            if (isset($jsonData->title)) {
                $title_updated = true;
                $queryFields .= "title = :title, ";
            }

            if (isset($jsonData->description)) {
                $description_updated = true;
                $queryFields .= "description = :description, ";
            }

            if (isset($jsonData->deadline)) {
                $deadline_updated = true;
                $queryFields .= "deadline = SRT_TO_DATE(:deadline, '%d/%m/%Y %H:%i'), ";
            }

            if (isset($jsonData->completed)) {
                $completed_updated = true;
                $queryFields .= "completed = :completed, ";
            }
            //  remove the last comma
            $queryFields = rtrim($queryFields, ", ");
            
            if (!$title_updated && !$deadline_updated && !$description_updated && !$completed_updated) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Nothing to update");
                $response->send();

                exit;
            }

            //  retrive the row that needs to be updated
            $sql = 'SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") deadline, completed
                    FROM tbltasks
                    WHERE id = :taskid
                    AND userid = :userid';
            $query = $writeDB->prepare($sql);    
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT);
            $query->execute();
            
            $rowCount = $query->rowCount();

            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("No task found to update");
                $response->send();

                exit;
            }

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task(
                    $row['id'],
                    $row['title'],
                    $row['description'],
                    $row['deadline'],
                    $row['completed']
                );
            }

            $sql = 'UPDATE tbltasks SET '.$queryFields
                  .' WHERE id = :taskid
                     AND userid = :userid';
            $query = $writeDB->prepare($sql);
            

            if ($title_updated) {
                //  format and than retrive
                $task->setTitle($jsonData->title);
                $updated_title = $task->getTitle();
                $query->bindParam(':title', $updated_title, PDO::PARAM_STR);
            }

            if ($description_updated) {
                //  format and than retrive
                $task->setDescription($jsonData->description);
                $updated_description = $task->getDescription();
                $query->bindParam(':description', $updated_description, PDO::PARAM_STR);
            }

            if ($deadline_updated) {
                //  format and than retrive
                $task->setDeadline($jsonData->deadline);
                $updated_deadline = $task->getDeadline();
                $query->bindParam(':dealine', $updated_deadline, PDO::PARAM_STR);
            }

            if ($completed_updated) {
                //  format and than retrive
                $task->setCompleted($jsonData->completed);
                $updated_completed = $task->getCompleted();
                $query->bindParam(':completed', $updated_completed, PDO::PARAM_STR);
            }

            //  bind the taskid
            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            if ($rowCount !== 1) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Task not updated");
                $response->send();

                exit;
            }

            //  send the updated task after retriving it from the DB
            $sql = 'SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") deadline, completed
                    FROM tbltasks
                    WHERE id = :taskid
                    AND userid = :userid';
            $query = $writeDB->prepare($sql);

            $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT);
            $query->execute();

            $taskArray = array();

            $rowCount = $query->rowCount();

            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed retrive task after update");
                $response->send();

                exit;
            }

            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task(
                    $row['id'],
                    $row['title'],
                    $row['description'],
                    $row['deadline'],
                    $row['completed']
                );

                $taskArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;
            
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage("Task Updated");
            $response->setData($returnData);
            $response->send();

            exit;
        } catch (PDOException $ex) {
            error_log("DB query error - ".$ex, 0);

            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to update task - Check data".$ex->getMessage());
            $response->send();

            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();

            exit;
        }
    } else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage("Request method not allowed");
        $response->send();

        exit;
    }
} elseif (array_key_exists("completed", $_GET)) {
    //  example url v1/tasks/complete -> task.php?completed=N
    // v1/tasks/incomplete -> task.php?completed=Y

    $completed = $_GET['completed'];

    if ($completed !== 'Y' && $completed !== 'N') {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage("Completed filter must be N or Y");
        $response->send();

        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        try {
            $sql = 'SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") deadline, completed
                    FROM tbltasks
                    WHERE completed = :completed
                    AND userid = :userid';
            $query = $readDB->prepare($sql);
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();
            $tasksArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task(
                    $row['id'],
                    $row['title'],
                    $row['description'],
                    $row['deadline'],
                    $row['completed']
                );

                //  Append each row received
                $tasksArray[] = $task->returnTaskAsArray();
            }

            //  prepare the response data
            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $tasksArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();

            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - ".ex, 0);

            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get the tasks");
            $response->send();

            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();

            exit;
        }

    } else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMesage("Request method not allowed");
        $response->send();

        exit;
    }
} elseif (array_key_exists("page", $_GET)) {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $page = $_GET['page'];

        if($page == '' || !is_numeric($page)) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage("Page number cannot be blank and must be numeric");
            $response->send();

            exit;
        }

        $limitPerPage = 20;

        try {
            //  get table rowcount to prepare the pagination
            $sql = 'SELECT count(*) totalNoTasks from tbltasks';
            $query = $readDB->prepare($sql);
            $query->execute();

            $row = $query->fetch(PDO::FETCH_ASSOC);

            $tasksCount = intval($row['totalNoTasks']);

            //  calc how many pages needed
            $numOfPages = ceil($tasksCount / $limitPerPage);

            if ($numOfPages === 0) {
                $numOfPages = 1;
            }

            if ($page <= 0 || $page > $numOfPages) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage("Page not found");
                $response->send();

                exit;
            }

            $offset = ($page == 1 ? 0 : ($limitPerPage * ($page - 1)));

            $sql = 'SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") deadline, completed
                    FROM tbltasks
                    WHERE userid = :userid
                    LIMIT :pglimit
                    OFFSET :offset';
            $query = $readDB->prepare($sql);
            $query->bindParam(':pglimit', $limitPerPage, PDO::PARAM_INT);
            $query->bindParam(':offset', $offset, PDO::PARAM_INT);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            $taskArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task(
                    $row['id'],
                    $row['title'],
                    $row['description'],
                    $row['deadline'],
                    $row['completed']
                );

                $taskArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();

            $returnData['rows_returned'] = $rowCount;
            $returnData['total_rows'] = $tasksCount;
            $returnData['total_pages'] = $numOfPages;
            $returnData['has_next_page'] = $page < $numOfPages;
            $returnData['has_previous_page'] = $page > 1;
            $returnData['tasks'] = $taskArray;
            
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();

            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - ".$ex, 0);

            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get tasks");
            $response->send();

            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessge());
            $response->send();

            exit;
        }

    } else {
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage("Request Method not allowed");

        exit;
    }

} elseif (empty($_GET)) {
    //  url expample v1/tasks/
    if($_SERVER['REQUEST_METHOD'] === 'GET') {
        try {
            $sql = 'SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") deadline, completed
                    FROM tbltasks
                    WHERE userid = :userid';
            $query = $readDB->prepare($sql);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT);
            $query->execute();
    
            $rowCount = $query->rowCount();
            $tasksArray = array();
    
            while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task(
                    $row['id'],
                    $row['title'],
                    $row['description'],
                    $row['deadline'],
                    $row['completed']
                );
    
                //  Append each row received
                $tasksArray[] = $task->returnTaskAsArray();
            }
    
            //  prepare the response data
            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $tasksArray;
    
            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
    
            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - ".ex, 0);

            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to get the tasks");
            $response->send();

            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();

            exit;
        }

    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        //  create a new task
        try {
            //  check that content type is json
            if($_SERVER['CONTENT_TYPE'] !== 'application/json') {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Content type header is not set to JSON");
                $response->send();

                exit;
            }
            //  inpent the body of the request
            $rawPOSTData = file_get_contents('php://input');

            if (!$jsonData = json_decode($rawPOSTData)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("Request body is not valid JSON");
                $response->send();

                exit;
            }

            //  check if the client provided the mandatory fields
            if (!isset($jsonData->title ) || !isset($jsonData->completed)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                !isset($jsonData->title) ? 
                    $response->addMessage("Title field mandatory and must be provided") : false;
                !isset($jsonData->completed) ? 
                    $response->addMessage("Completed field mandatory and must be provided") : false;    
                $response->send();

                exit;
            }

            //  prepare a task to pass the data
            $newTask = new Task(
                null,
                $jsonData->title,
                isset($jsonData->description) ? $jsonData->description : null,
                isset($jsonData->deadline) ? $jsonData->deadline : null,
                $jsonData->completed
            );

            $title = $newTask->getTitle();
            $description = $newTask->getDescription();
            $deadline = $newTask->getDeadline();
            $completed = $newTask->getCompleted();

            $sql = 'INSERT INTO tbltasks (title, description, deadline, completed, userid)
                    VALUES (:title, :description, STR_TO_DATE(:deadline, \'%d/%m/%Y %H:%i\'), :completed, :userid)';
            $query = $writeDB->prepare($sql);
            $query->bindParam(':title', $title, PDO::PARAM_STR);   
            $query->bindParam(':description', $description, PDO::PARAM_STR);   
            $query->bindParam(':deadline', $deadline, PDO::PARAM_STR);   
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT); 
            
            $query->execute();

            $rowCount = $query->rowCount();

            if ($rowCount === 0 ){
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed to insert task");
                $response->send();

                exit;
            }

            //  return the same data with the id
            //  getting the last inserted id
            $lastTaskId = $writeDB->lastInsertId();

            $sql = 'SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") deadline, completed
                    FROM tbltasks
                    WHERE id = :taskid
                    AND userid = :userid';
            $query = $writeDB->prepare($sql);

            $query->bindParam(':taskid', $lastTaskId, PDO::PARAM_INT);
            $query->bindParam(':userid', $returnUserId, PDO::PARAM_INT);
            $query->execute();

            $taskArray = array();

            $rowCount = $query->rowCount();

            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage("Failed retrive task after creation");
                $response->send();

                exit;
            }

            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $task = new Task(
                    $row['id'],
                    $row['title'],
                    $row['description'],
                    $row['deadline'],
                    $row['completed']
                );

                $taskArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['tasks'] = $taskArray;
            
            $response = new Response();
            $response->setHttpStatusCode(201);
            $response->setSuccess(true);
            $response->addMessage("Task Created");
            $response->setData($returnData);
            $response->send();

            exit;
        } catch (PDOException $ex) {
            error_log("Database query error - ".ex, 0);

            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage("Failed to create task");
            $response->send();

            exit;
        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();

            exit;
        }
    } else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMesage("Request method not allowed");
        $response->send();

        exit;
    }
} else {
    $response = new Response();
    $response->setHttpStatusCode(404);
    $response->setSuccess(false);
    $response->addMesage("Endpoint not found");
    $response->send();

    exit;
}