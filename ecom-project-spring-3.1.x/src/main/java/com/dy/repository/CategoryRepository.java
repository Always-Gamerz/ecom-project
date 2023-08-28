package com.dy.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dy.Model.Category;


public interface CategoryRepository extends JpaRepository<Category,Integer>{
	

}
