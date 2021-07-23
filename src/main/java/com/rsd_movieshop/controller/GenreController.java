package com.rsd_movieshop.controller;

import com.rsd_movieshop.model.Genre;
import com.rsd_movieshop.service.GenreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;

@RestController
@RequestMapping(path = "/genre")
public class GenreController {

	private final GenreService genreService;


	public GenreController(GenreService genreService) {
		this.genreService = genreService;
	}


	@GetMapping("/{genreID}")
	public Genre getGenre (@PathVariable int genreID){
		// return specific genre
		System.out.println("GenreController: ");
		return null;
	}
	
	@GetMapping
	public ArrayList<Genre> getGenres() {
		// return all orders
		System.out.println("GenreController: getAllOrders");
		return null;
	}
	
	@PostMapping
	public void addNewGenre(@RequestBody Genre genre) {
		System.out.println("GenreController: addNewGenre");
	}
	
	@PutMapping(path = "/{genreID}")
	public void updateGenre(@PathVariable int genreID) {
		System.out.println("GenreController: updateGenre");
	}
	
	@DeleteMapping(path = "/{genreID}")
	public void deleteGenre(@PathVariable int genreID) {
		System.out.println("GenreController: deleteGenre");
	}
}