package com.rsd_movieshop.model;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

@Entity
@Table(name = "genre")
public class Genre {
	@Id
	@SequenceGenerator(name = "genre_seq", allocationSize = 1)
	@GeneratedValue(generator = "genre_seq")
	@Column(name = "genre_id")
	private long genreId;

	@Column(name = "Genre_Name", unique = true)
	private String movieGenre;

	@ManyToMany(mappedBy = "genres")
	private List<Movie> movies = new ArrayList<>();

	

	public Genre() {
		super();
	}

	public Genre(String movieGenre, List<Movie> movies) {
		this.movieGenre = movieGenre;
		this.movies = movies;
	}
	
	public Genre(String movieGenre) {
		this.movieGenre = movieGenre;
	}

	public long getGenreID() {
		return genreId;
	}
	
	public void setGenreID(long genreID) {
		this.genreId = genreID;
	}
	
	public String getMovieGenre() {
		return movieGenre;
	}
	
	public void setMovieGenre(String movieGenre) {
		this.movieGenre = movieGenre;
	}

	public List<Movie> getMovies() {
		return movies;
	}

	public void setMovies(List<Movie> movies) {
		this.movies = movies;
	}

	
}
