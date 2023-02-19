package com.ding.dao;

import com.ding.entities.Role;
import com.ding.entities.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface UserDao {
    //根据用户名查询用户
    User loadUserByUsername(@Param("username") String username);
  	
  	//根据用户id查询角色
  	List<Role> getRolesByUid(@Param("uid") Integer uid);
}