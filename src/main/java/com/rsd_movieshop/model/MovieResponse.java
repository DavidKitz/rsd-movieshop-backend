package com.rsd_movieshop.model;

import java.util.List;

public class MovieResponse {

	private String name;
	private int releaseYear;
	private List<String> genres;
	private double price;
	private int amountInStock;

	public MovieResponse(String name, int releaseYear, List<String> genres, double price, int amountInStock) {
		super();
		this.name = name;
		this.releaseYear = releaseYear;
		this.genres = genres;
		this.price = price;
		this.amountInStock = amountInStock;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public int getReleaseYear() {
		return releaseYear;
	}

	public void setReleaseYear(int releaseYear) {
		this.releaseYear = releaseYear;
	}

	public List<String> getGenres() {
		return genres;
	}

	public void setGenres(List<String> genres) {
		this.genres = genres;
	}

	public double getPrice() {
		return price;
	}

	public void setPrice(double price) {
		this.price = price;
	}

	public int getAmountInStock() {
		return amountInStock;
	}

	public void setAmountInStock(int amountInStock) {
		this.amountInStock = amountInStock;
	}

}