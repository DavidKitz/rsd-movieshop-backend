package com.rsd_movieshop.controller;

import com.rsd_movieshop.model.User;
import com.rsd_movieshop.service.UserService;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
@RestController
@RequestMapping(path = "/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }


    @GetMapping
    public ArrayList<User> getUsers() {
        //get all users
        return null;
    }

    @GetMapping("/{userID}")
    public User getUser(@PathVariable int userID) {
        //Informationen zu spezifischem user
        return null;
    }

    @PostMapping
    public void addUser(@RequestBody User user) {
        //Hinzufügen eines users
    }

    @PutMapping("/{userID}")
    public void updateUser(@PathVariable int userID) {
        //update user data
    }
    @DeleteMapping("/{userID}")
    public void deleteUser(@PathVariable int userID) {
        //Delete user with id
    }
}