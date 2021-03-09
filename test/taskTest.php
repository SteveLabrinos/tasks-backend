<?php

/**
 * test if the task model is providing a correct json format after
 * validating user input
 * @author Steve Labrinos [stalab at linuxmail.org] on 6/3/2021
 */

require_once('../model/Task.php');

try {
    $task = new Task(
        4,
        "Title Here",
        "Description Here",
        "01/01/1970 12:00",
        "Y"
    );

    header('Content-type: application/json;charset=UTF-8');
    echo json_encode($task->returnTaskAsArray());

} catch (TaskException $ex) {
    echo "Error: ".$ex->getMessage();
}