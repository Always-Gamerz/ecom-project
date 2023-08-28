package com.dy.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dy.Model.Cart;
import com.dy.Model.User;


public interface CartRepository extends JpaRepository<Cart,Integer> {
	public Optional<Cart>findByUser(User user);
	
	  
}
