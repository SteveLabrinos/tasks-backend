<?php

/**
 * Static implementation of master slave DB connection model
 * @author Steve Labrinos [stalab at linuxmail.org] on 6/3/2021
 */

class DB {
    //  master DB
    private static $writeDBConnection;
    //  slave DB workers
    private static $readDBConnection;

    public static function connectWriteDB() {
        if (self::$writeDBConnection === null) {
            self::$writeDBConnection = new PDO('mysql:host=localhost;dbname=tasksdb;charset=utf8', 'root', '1234');
            self::$writeDBConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$writeDBConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        }

        return self::$writeDBConnection;
    }

    //  workers. In XAMPP env is the same as the master
    public static function connectReadDB() {
        if (self::$readDBConnection === null) {
            self::$readDBConnection = new PDO('mysql:host=localhost;dbname=tasksdb;charset=utf8', 'root', '1234');
            self::$readDBConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$readDBConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        }

        return self::$readDBConnection;
    }
}