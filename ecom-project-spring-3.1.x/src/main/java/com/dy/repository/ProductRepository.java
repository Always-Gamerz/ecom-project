package com.dy.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import com.dy.Model.Category;
import com.dy.Model.Product;


public interface ProductRepository extends JpaRepository<Product,Integer> {
	Page<Product> findByCategory(Category catgoty,Pageable pageable);
}
