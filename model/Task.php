<?php

/**
 * 
 * @author Steve Labrinos [stalab at linuxmail.org] on 6/3/2021
 */

 class TaskException extends Exception { }

 class Task {
    private $_id;
    private $_title;
    private $_description;
    private $_deadline;
    private $_completed;

    //  constructor
    public function __construct($id, $title, $description, $deadline, $completed) {
        $this->setId($id);
        $this->setTitle($title);
        $this->setDescription($description);
        $this->setDeadline($deadline);
        $this->setCompleted($completed);
    }

    //  setters
    public function getId() {
        return $this->_id;
    }

    public function getTitle() {
        return $this->_title;
    }

    public function getDescription() {
        return $this->_description;
    }

    public function getDeadline() {
        return $this->_deadline;
    }

    public function getCompleted() {
        return $this->_completed;
    }

    //  setters
    public function setId($id) {
        //  check if the argument is not numeric or negative number
        //  or the object has an id value
        if(($id !== null) && (!is_numeric($id) || $id <=0 || $this->_id !== null)) {
            throw new TaskException("Task ID Error");
        }

        $this->_id = $id;
    }

    public function setTitle($title) {

        if(strlen($title) < 0 || strlen($title) > 255) {
            throw new TaskException("Task Title Error");
        }

        $this->_title = $title;
    }

    public function setDescription($description) {

        if(($description !== null) && (strlen($description) > 16777215 )) {
            throw new TaskException("Task Description Error");
        }

        $this->_description = $description;
    }

    public function setDeadline($deadline) {
        if(($deadline !== null) 
            && date_format(date_create_from_format('d/m/Y H:i', $deadline), 'd/m/Y H:i') !== $deadline) {
            throw new TaskException("Task Deadline date time Error");
        }

        $this->_deadline = $deadline;
    }

    public function setCompleted($completed) {
        if(strtoupper($completed) !== 'Y' && strtoupper($completed) !== 'N') {
            throw new TaskException("Task Completed must be a Y or N");
        }

        $this->_completed = $completed;
    }

    public function returnTaskAsArray() {
        $task = array();

        $task['id'] = $this->getId();
        $task['title'] = $this->getTitle();
        $task['description'] = $this->getDescription();
        $task['deadline'] = $this->getDeadline();
        $task['completed'] = $this->getCompleted();

        return $task;
    }
 }