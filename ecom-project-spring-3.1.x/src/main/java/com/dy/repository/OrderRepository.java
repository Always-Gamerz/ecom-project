package com.dy.repository;



import org.springframework.data.jpa.repository.JpaRepository;

import com.dy.Model.Order;


public interface OrderRepository extends JpaRepository<Order,Integer>{

}
