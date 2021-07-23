package com.rsd_movieshop.model;

import java.util.List;

public class Cart {
    private List<CartItem> movieOrder;
    private int cartID;

    public Cart() {
    }

    public List<CartItem> getMovieOrder() {
        return movieOrder;
    }

    public void setMovieOrder(List<CartItem> movieOrder) {
        this.movieOrder = movieOrder;
    }

    public int getCartID() {
        return cartID;
    }

    public void setCartID(int cartID) {
        this.cartID = cartID;
    }

    public Cart(List<CartItem> movieOrder, int cartID) {
        this.movieOrder = movieOrder;
        this.cartID = cartID;
    }

    @Override
    public String toString() {
        return "Cart{" +
                "movieOrder=" + movieOrder +
                ", cartID=" + cartID +
                '}';
    }
}